require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const stripe = require("stripe")(process.env.VITE_SECRET_KEY);

const port = process.env.PORT || 9000;
const app = express();
// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://parcel-ease-76d37.web.app",
    "https://parcel-ease-76d37.firebaseapp.com",
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  console.log("Token received:", token);

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log("Token verification error:", err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.whalj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  const usersCollection = client.db("parcelEase").collection("users");
  const parcelsCollection = client.db("parcelEase").collection("parcels");
  const deliveryMenCollection = client
    .db("parcelEase")
    .collection("deliveryMen");
  const notificationsCollection = client
    .db("parcelEase")
    .collection("notifications");
  const reviewsCollection = client.db("parcelEase").collection("reviews");
  const locationsCollection = client.db("parcelEase").collection("locations");

  try {
    app.post("/jwt", async (req, res) => {
      const email = req.body;
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "365d",
      });

      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true, token });
    });

    app.get("/logout", async (req, res) => {
      try {
        res
          .clearCookie("token", {
            maxAge: 0,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
      } catch (err) {
        res.status(500).send(err);
      }
    });

    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const user = await usersCollection.findOne({ email });
        if (user?.role !== "admin") {
          return res.status(403).send({ message: "Admin access required" });
        }

        next();
      } catch (err) {
        console.error("Error verifying admin:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    };
    const verifyDeliveryman = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const user = await usersCollection.findOne({ email });
        if (user?.role !== "deliverymen") {
          return res
            .status(403)
            .send({ message: "Deliveryman access required" });
        }

        next();
      } catch (err) {
        console.error("Error verifying deliveryman:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    };
    const verifyAdminOrDeliveryman = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const user = await usersCollection.findOne({ email });
        if (user?.role === "admin" || user?.role === "deliverymen") {
          return next();
        }

        res
          .status(403)
          .send({ message: "Access restricted to admins or deliverymen" });
      } catch (err) {
        console.error("Error verifying admin or deliveryman:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    };

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const { page = 1, limit = 5 } = req.query;
      const skip = (page - 1) * limit;

      try {
        const total = await usersCollection.countDocuments();
        const users = await usersCollection
          .find()
          .skip(skip)
          .limit(Number(limit))
          .toArray();

        res.send({ users, total });
      } catch (err) {
        console.error("Error fetching users:", err);
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        const result = await usersCollection.insertOne(user);
        res.status(201).send(result);
      } catch (error) {
        console.error("Error saving user:", error);
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    app.get("/users/:email", async (req, res) => {
      const email = req.params.email.toLowerCase();
      console.log("Fetching user for email:", email);

      const user = await usersCollection.findOne({ email });
      console.log("User found:", user);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json(user);
    });

    app.post("/users/:email", async (req, res) => {
      const email = req.params.email;
      const userData = req.body;

      try {
        const userExists = await usersCollection.findOne({ email });

        if (userExists) {
          return res.status(400).send({ message: "Email already registered" });
        }

        const result = await usersCollection.insertOne({
          email: email,
          ...userData,
        });

        res.send({
          success: true,
          message: "User created successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to create user",
          error: error.message,
        });
      }
    });
    app.patch("/users/:id", async (req, res) => {
      const { id } = req.params;
      const { type } = req.body;

      if (!ObjectId.isValid(id)) {
        return res
          .status(400)
          .send({ success: false, message: "Invalid User ID" });
      }

      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });

        if (!user) {
          return res
            .status(404)
            .send({ success: false, message: "User not found" });
        }

        if (user.role === type) {
          return res
            .status(400)
            .send({ success: false, message: `User is already a ${type}` });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role: type } }
        );

        res.send({
          success: true,
          message: `User role updated from ${user.role} to ${type}`,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to update user role",
          error: error.message,
        });
      }
    });

    app.post("/bookParcel", verifyToken, async (req, res) => {
      const {
        name,
        email,
        phone,
        parcelType,
        parcelWeight,
        price,
        receiverName,
        receiverPhone,
        deliveryAddress,
        deliveryDate,
        latitude,
        longitude,
      } = req.body;

      if (
        !name ||
        !email ||
        !phone ||
        !parcelType ||
        !parcelWeight ||
        !receiverName ||
        !receiverPhone ||
        !deliveryAddress ||
        !deliveryDate ||
        !latitude ||
        !longitude
      ) {
        return res.status(400).send({
          success: false,
          message: "All fields are required.",
        });
      }

      if (isNaN(parseFloat(latitude)) || isNaN(parseFloat(longitude))) {
        return res.status(400).send({
          success: false,
          message: "Latitude and Longitude must be valid numbers.",
        });
      }

      const newParcel = {
        name,
        email,
        phone,
        parcelType,
        parcelWeight: parseFloat(parcelWeight),
        price,
        receiverName,
        receiverPhone,
        deliveryAddress,
        deliveryDate,
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        status: "pending",
        createdAt: new Date(),
      };

      try {
        const result = await parcelsCollection.insertOne(newParcel);

        const user = await usersCollection.findOne({ email });
        if (user) {
          await usersCollection.updateOne(
            { email },
            { $inc: { totalParcelBooked: 1 } }
          );
        } else {
          await usersCollection.insertOne({
            email,
            totalParcelBooked: 1,
          });
        }

        const adminUsers = await usersCollection
          .find({ role: "admin" })
          .toArray();
        const notifications = adminUsers.map((admin) => ({
          email: admin.email,
          image: admin.image,
          message: `New parcel booked by ${name}`,
          read: false,
          createdAt: new Date(),
        }));
        await notificationsCollection.insertMany(notifications);

        res.send({
          success: true,
          message: "Parcel booked successfully!",
          parcelId: result.insertedId,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to book parcel.",
          error: error.message,
        });
      }
    });

    app.get("/my-parcels", verifyToken, async (req, res) => {
      const { email } = req.query;

      if (!email) {
        return res.status(400).send({ message: "Email is required" });
      }

      try {
        const parcels = await parcelsCollection
          .find({ email })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(parcels);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch parcels",
          error: error.message,
        });
      }
    });
    app.get("/locations", async (req, res) => {
      try {
        const locations = await locationsCollection.find().toArray();
        res.json(locations);
      } catch (error) {
        res.status(500).json({ message: "Error fetching locations", error });
      }
    });

    app.patch("/cancel-parcel/:id", verifyToken, async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid parcel ID" });
      }

      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id), status: "pending" },
          { $set: { status: "canceled" } }
        );

        if (result.matchedCount === 0) {
          return res.status(400).send({
            message: "Parcel not found or not eligible for cancellation",
          });
        }

        res.send({ success: true, message: "Parcel canceled successfully" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to cancel the parcel",
          error: error.message,
        });
      }
    });

    app.patch("/update-parcel/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const updates = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid parcel ID" });
      }

      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updates }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Parcel not found" });
        }

        res.send({ success: true, message: "Parcel updated successfully" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to update the parcel",
          error: error.message,
        });
      }
    });
    app.get(
      "/parcels",
      verifyToken,
      verifyAdminOrDeliveryman,
      async (req, res) => {
        const { from, to, deliveryManId } = req.query;
        const query = {};

        if (from && to) {
          query.deliveryDate = {
            $gte: new Date(from),
            $lte: new Date(to),
          };
        }

        if (deliveryManId) {
          query.deliveryManId = deliveryManId;
        }

        try {
          const parcels = await parcelsCollection.find(query).toArray();
          res.send(parcels);
        } catch (error) {
          res
            .status(500)
            .send({ message: "Failed to fetch parcels", error: error.message });
        }
      }
    );

    app.get("/parcels/search", async (req, res) => {
      const { from, to } = req.query;

      const parcels = await parcelsCollection
        .find({
          deliveryDate: {
            $gte: new Date(from),
            $lte: new Date(to),
          },
        })
        .toArray();

      res.send(parcels);
    });

    app.get("/parcels/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res
          .status(400)
          .send({ success: false, message: "Invalid Parcel ID" });
      }
      try {
        const parcel = await parcelsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!parcel) {
          return res
            .status(404)
            .send({ success: false, message: "Parcel not found" });
        }

        res.send(parcel);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch the parcel",
          error: error.message,
        });
      }
    });
    app.put("/parcels/:id", async (req, res) => {
      const { id } = req.params;
      const updatedData = req.body;

      if (!ObjectId.isValid(id)) {
        return res
          .status(400)
          .send({ success: false, message: "Invalid Parcel ID" });
      }
      try {
        const parcel = await parcelsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!parcel) {
          return res
            .status(404)
            .send({ success: false, message: "Parcel not found" });
        }

        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: updatedData,
          }
        );
        if (result.modifiedCount === 0) {
          return res
            .status(400)
            .send({ success: false, message: "No changes made" });
        }
        res.send({ success: true, message: "Parcel updated successfully" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to update the parcel",
          error: error.message,
        });
      }
    });
    app.patch("/parcels/:id", async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid Parcel ID" });
      }
      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: req.body }
        );
        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ message: "Parcel not found or no changes made" });
        }
        res.send({ success: true, message: "Parcel updated successfully" });
      } catch (err) {
        res
          .status(500)
          .send({ message: "Error updating parcel", error: err.message });
      }
    });
    app.patch("/update-parcel/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      if (!id) {
        return res.status(400).send({ message: "Parcel ID is required" });
      }
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid parcel ID" });
      }
      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: req.body }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Parcel not found" });
        }
        res.send({ success: true, message: "Parcel updated successfully" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to update the parcel",
          error: error.message,
        });
      }
    });

    app.patch(
      "/assign-parcel/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { deliveryManId } = req.body;

        if (!ObjectId.isValid(id) || !ObjectId.isValid(deliveryManId)) {
          return res
            .status(400)
            .send({ message: "Invalid parcel or delivery man ID" });
        }

        try {
          const result = await parcelsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { deliveryManId, status: "assigned" } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "Parcel not found" });
          }

          const deliveryMan = await usersCollection.findOne({
            _id: new ObjectId(deliveryManId),
          });
          if (deliveryMan) {
            await notificationsCollection.insertOne({
              email: deliveryMan.email,
              message: `You have been assigned a new parcel`,
              read: false,
              createdAt: new Date(),
            });
          }

          // Send notification to user
          const parcel = await parcelsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (parcel && parcel.email) {
            await notificationsCollection.insertOne({
              email: parcel.email,
              message: `Your parcel has been assigned to a delivery man`,
              read: false,
              createdAt: new Date(),
            });
          }

          res.send({ success: true, message: "Parcel assigned successfully" });
        } catch (error) {
          res.status(500).send({
            success: false,
            message: "Failed to assign parcel",
            error: error.message,
          });
        }
      }
    );

    // Update parcel status (deliver or cancel)
    app.patch("/update-parcel-status/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const { status } = req.body;

      if (
        !ObjectId.isValid(id) ||
        !["delivered", "canceled"].includes(status)
      ) {
        return res.status(400).send({ message: "Invalid parcel ID or status" });
      }

      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Parcel not found" });
        }

        // Send notification to delivery man
        const parcel = await parcelsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (parcel && parcel.deliveryManId) {
          const deliveryMan = await usersCollection.findOne({
            _id: new ObjectId(parcel.deliveryManId),
          });
          if (deliveryMan) {
            await notificationsCollection.insertOne({
              email: deliveryMan.email,
              image: deliveryMan.image,
              message: `Parcel has been ${status}`,
              read: false,
              createdAt: new Date(),
            });
          }
        }

        // Send notification to user
        if (parcel && parcel.email) {
          await notificationsCollection.insertOne({
            email: parcel.email,
            image: parcel.image,
            message: `Your parcel has been ${status}`,
            read: false,
            createdAt: new Date(),
          });
        }

        res.send({ success: true, message: `Parcel ${status} successfully` });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: `Failed to update parcel status to ${status}`,
          error: error.message,
        });
      }
    });

    // Fetch all delivery men
    app.get("/deliverymen", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const deliverymenUsers = await usersCollection
          .find({ role: "deliverymen" })
          .toArray();
        res.status(200).json(deliverymenUsers);
      } catch (error) {
        console.error("Error fetching deliverymen users:", error);
        res.status(500).json({
          message: "Server error, unable to fetch deliverymen users.",
        });
      }
    });
    app.get("/delivery-man/:deliveryManId", verifyToken, async (req, res) => {
      const { deliveryManId } = req.params;

      if (!deliveryManId) {
        return res.status(400).send({ message: "Delivery Man ID is required" });
      }

      try {
        const parcels = await parcelsCollection
          .find({ deliveryManId })
          .toArray();

        res.json(parcels);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch parcels for the delivery man",
          error: error.message,
        });
      }
    });
    app.get("/deliveryMan/:id", async (req, res) => {
      const { id } = req.params;
      try {
        const deliveryMan = await usersCollection.findOne({
          _id: new ObjectId(id),
          role: "deliverymen",
        });
        if (!deliveryMan) {
          return res.status(404).send({ message: "Delivery man not found" });
        }

        const totalDelivered = deliveryMan.totalDelivered || 0;
        res.send({ ...deliveryMan, totalDelivered });
      } catch (error) {
        res.status(500).send({ message: "Server error", error: error.message });
      }
    });

    app.patch("/delivery-man/:deliveryManId", async (req, res) => {
      const { deliveryManId } = req.params;
      if (!ObjectId.isValid(deliveryManId)) {
        return res.status(400).json({ message: "❌ Invalid Delivery Man ID" });
      }
      try {
        const filter = {
          _id: new ObjectId(deliveryManId),
          role: "deliverymen",
        };

        const deliveryMan = await usersCollection.findOne(filter);

        if (!deliveryMan) {
          return res.status(404).json({
            success: false,
            message: "❌ Delivery man not found in the database.",
          });
        }
        const result = await usersCollection.findOneAndUpdate(
          filter,
          {
            $inc: { totalDelivered: 1 },
            $set: { deliveryDate: new Date() },
          },
          { returnDocument: "after" }
        );
        res.status(200).json({
          success: true,
          message: "✅ Total delivered updated successfully",
          deliveryMan: result.value,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "❌ Server error, unable to update totalDelivered",
          error: error.message,
        });
      }
    });
    app.post("/review", async (req, res) => {
      const { userName, userImage, rating, feedback, deliveryManId, parcelId } =
        req.body;

      if (!userName || !rating || !feedback || !deliveryManId || !parcelId) {
        return res
          .status(400)
          .json({ success: false, message: "All fields are required." });
      }

      const newReview = {
        userName,
        userImage,
        rating: parseFloat(rating),
        feedback,
        deliveryManId: new ObjectId(deliveryManId),
        parcelId,
        createdAt: new Date(),
      };
      console.log(newReview);

      try {
        await reviewsCollection.insertOne(newReview);

        const reviews = await reviewsCollection
          .find({ deliveryManId: new ObjectId(deliveryManId) })
          .toArray();

        const totalRatings = reviews.reduce(
          (sum, review) => sum + review.rating,
          0
        );
        const averageRating = (totalRatings / reviews.length).toFixed(2);

        await usersCollection.updateOne(
          { _id: new ObjectId(deliveryManId), role: "deliverymen" },
          { $set: { averageRating: parseFloat(averageRating) } }
        );

        res.status(201).json({
          success: true,
          message: "Review submitted and rating updated successfully",
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to submit review",
          error: error.message,
        });
      }
    });
    app.get("/reviews", verifyToken, verifyDeliveryman, async (req, res) => {
      const { deliveryManId } = req.query;

      if (!deliveryManId) {
        return res
          .status(400)
          .json({ success: false, message: "DeliveryMan ID required" });
      }
      try {
        const reviews = await reviewsCollection
          .find({ deliveryManId: new ObjectId(deliveryManId) })
          .toArray();
        res.status(200).json(reviews);
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Error fetching reviews",
          error: error.message,
        });
      }
    });
    app.get("/top-deliverymen", async (req, res) => {
      try {
        const topDeliveryMen = await usersCollection
          .aggregate([
            {
              $match: { role: "deliverymen" },
            },
            {
              $lookup: {
                from: "reviews",
                localField: "_id",
                foreignField: "deliveryManId",
                as: "reviews",
              },
            },
            {
              $addFields: {
                averageRating: {
                  $cond: [
                    { $gt: [{ $size: "$reviews" }, 0] },
                    { $avg: "$reviews.rating" },
                    null,
                  ],
                },
              },
            },
            {
              $project: {
                name: 1,
                image: 1,
                deliveredParcels: "$totalDelivered",
                averageRating: 1,
              },
            },
            {
              $sort: { averageRating: -1 },
            },
          ])
          .toArray();

        res.status(200).json({
          success: true,
          deliveryMen: topDeliveryMen,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to fetch top delivery men",
          error: error.message,
        });
      }
    });
    // Statistics Route
    app.get("/stats", async (req, res) => {
      try {
        const parcelsBooked = await parcelsCollection.countDocuments();
        const parcelsDelivered = await parcelsCollection.countDocuments({
          status: "Delivered",
        });
        const totalUsers = await usersCollection.countDocuments();

        res.send({
          parcelsBooked,
          parcelsDelivered,
          totalUsers,
        });
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch statistics", error });
      }
    });
    app.get("/stats/charts", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const bookingsByDate = await parcelsCollection
          .aggregate([
            {
              $group: {
                _id: {
                  $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                },
                count: { $sum: 1 },
              },
            },
            { $sort: { _id: 1 } },
          ])
          .toArray();

        const bookedVsDelivered = await parcelsCollection
          .aggregate([
            {
              $group: {
                _id: {
                  $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                },
                booked: { $sum: 1 },
                delivered: {
                  $sum: { $cond: [{ $eq: ["$status", "Delivered"] }, 1, 0] },
                },
              },
            },
            { $sort: { _id: 1 } },
          ])
          .toArray();

        res.send({
          bookingsByDate: bookingsByDate.map((item) => ({
            date: item._id,
            count: item.count,
          })),
          bookedVsDelivered: bookedVsDelivered.map((item) => ({
            date: item._id,
            booked: item.booked,
            delivered: item.delivered,
          })),
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch statistics",
          error: error.message,
        });
      }
    });

    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      const { amount } = req.body;

      if (!amount) {
        return res.status(400).send({ message: "Amount is required" });
      }

      try {
        console.log(`Creating payment intent for amount: ${amount}`);
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount * 100, // amount in cents
          currency: "usd",
        });

        console.log("Payment intent created successfully:", paymentIntent);

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error("Error creating payment intent:", error);
        res.status(500).send({
          message: "Failed to create payment intent",
          error: error.message,
        });
      }
    });

    // Fetch notifications for the logged-in user
    app.get("/notifications", verifyToken, async (req, res) => {
      const email = req.user?.email;
      if (!email) {
        return res.status(400).send({ message: "Email is required" });
      }

      try {
        const notifications = await notificationsCollection
          .find({ email })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(notifications);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch notifications",
          error: error.message,
        });
      }
    });

    app.patch("/notifications/read", verifyToken, async (req, res) => {
      const email = req.user?.email;

      if (!email) {
        return res.status(400).send({ message: "Email is required" });
      }

      try {
        await notificationsCollection.updateMany(
          { email, read: false },
          { $set: { read: true } }
        );
        res.send({ success: true, message: "Notifications marked as read" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to mark notifications as read",
          error: error.message,
        });
      }
    });

    app.patch("/notifications/:id/read", verifyToken, async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid notification ID" });
      }

      try {
        const result = await notificationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { read: true } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Notification not found" });
        }

        res.send({ success: true, message: "Notification marked as read" });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to mark notification as read",
          error: error.message,
        });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
    // console.log("MongoDB connection closed.");
  }
}
run().catch(console.dir);
app.get("/", (req, res) => {
  res.send("Hello from ParcelEase Server..");
});
app.listen(port, () => {
  console.log(`ParcelEase is running on port ${port}`);
});
