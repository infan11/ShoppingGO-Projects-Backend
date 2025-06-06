const express = require('express');
const cors = require('cors');
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion , ObjectId} = require('mongodb');
const port = process.env.PORT || 5000;
const stripe = require("stripe")(process.env.VITE_STRIPE_SECRET_KEY);
const jwt = require("jsonwebtoken");
const { default: axios } = require('axios');
// MIDDLEWERE
app.use(express.json())
app.use(cors());
app.use(express.urlencoded(
    { extended: true }
));




const uri = `mongodb+srv://${process.env.DBNAME}:${process.env.DBPASS}@cluster0.lopynog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;



// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
    try {


        const usersCollection = client.db("ShoppingGO").collection("users");
        // sellerProfile
        const sellerProfileCollection = client.db("ShoppingGO").collection("sellerProfile");
        const productsCollection = client.db("ShoppingGO").collection("products");
        const shoppingCartCollection = client.db("ShoppingGO").collection("shoppingCart");
        const paymentCollection = client.db("ShoppingGO").collection("payment");
        const districtCollection = client.db("ShoppingGO").collection("districtAvailable");
        const searchDataCollection = client.db("ShoppingGO").collection("search-data");
        // token create
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.JWT_WEB_TOKEN, { expiresIn: "2hr" })
            res.send({ token })
        });
        const verifyToken = (req, res, next) => {
            // console.log("inside verify token ", req.headers.authorization);
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "Unauthorized access" })
            }
            const token = req.headers.authorization.split(" ")[1];
            jwt.verify(token, process.env.JWT_WEB_TOKEN, (err, decoded) => {
                if (err) {
                    return res.status(403).send({ message: "forbiidden access" })
                }
                req.decoded = decoded;
                next();
            })
        }
        // serach data save 
        app.post("/search-data", async (req, res) => {
            const serachBar = req.body;
            const result = await searchDataCollection.insertOne(serachBar);
            res.send(result)
        })
        app.get("/search-data", verifyToken, async (req, res) => {
            const email = req.query.email; // changed from req.params
            const result = await searchDataCollection.find({ email }).toArray();
            res.send(result);
          });
          
          // DELETE (add keyword to params)
          app.delete("/search-data/:keyword", verifyToken, async (req, res) => {
            const keyword = decodeURIComponent(req.params.keyword);
            const result = await searchDataCollection.deleteOne({ keyword });
            res.send(result);
          });

        // verify admin 
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isAdmin = user?.role === "admin";
            if (!isAdmin) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }
        const verifyModerator = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isModerator = user?.role === "moderator";
            if (!isModerator) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }

        // Check if user is an admin

        app.get('/users/admin/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            // make sure the token's email matches the requested email
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' });
            }

            const user = await usersCollection.findOne({ email });
            const isAdmin = user?.role === 'admin';
            res.send({ admin: isAdmin });
        });

        // Check if user is a moderator
        app.get('/users/moderator/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' });
            }

            const user = await usersCollection.findOne({ email });
            const isModerator = user?.role === 'moderator';
            res.send({ moderator: isModerator });
        });
        // check user information
      app.get("/users/:id" ,  verifyToken , async (req, res) => {
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await usersCollection.findOne(query);
        res.send(result)
      })
        // Check if user is a restaurant seller

        app.get("/users", verifyToken, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.get('/users/check-name', async (req, res) => {
            try {
                const { name, email } = req.query;
                if (!name || !email) {
                    return res.status(400).json({ error: "Name and email are required." });
                }

                const existingUser = await usersCollection.findOne({
                    name: name.trim(),
                    email: { $ne: email } // ignore current user's name
                });

                res.json({ exists: !!existingUser });
            } catch (error) {
                console.error("Error checking name:", error);
                res.status(500).json({ error: "Internal server error." });
            }
        })
        // app.post("/users" , async (req, res) => {
        //     const userInfo = req.body;
        //     const result = await usersCollection.insertOne(userInfo);
        //     console.log(result);
        //     res.send(result)
        // })
        app.put("/users", async (req, res) => {
            const user = req.body;
            const query = { email: user?.email }
            const isExists = await usersCollection.findOne(query)
            if (isExists) return res.send(isExists)
            const options = { upsert: true }

            const updateDoc = {
                $set: {
                    ...user,
                    // uid: uid,
                    // displayName, photoURL,
                    date: Date.now(),
                    isNew: user.restaurantAdddress && user.restaurantNumber ? true : false,

                }

            }
            const result = await usersCollection.updateOne(query, updateDoc, options)
            res.send(result)
        })
        app.put("/users/:email", async (req, res) => {
            const email = req.params.email;
            const user = req.body;

            const query = { email };
            const options = { upsert: true };

            const updateDoc = {
                $set: {
                    name: user.name,
                    photo: user.photo,
                    email: user.email,
                    dob: user.dob,       
                    phoneNumber: user.phoneNumber,  
                    address: user.address

                }
            };

            try {
                const result = await usersCollection.updateOne(query, updateDoc, options);
                res.send(result);
            } catch (error) {
                console.error("Failed to update user:", error);
                res.status(500).send({ error: "Failed to update user" });
            }
        });
        app.delete("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await usersCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })

        // user verify admin 
        app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log(id);
            const filter = { _id: new ObjectId(id) }
            console.log(filter);
            const updateDoc = {
                $set: {
                    role: "admin"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log(result);
            res.send(result)
        })

        app.patch("/users/moderator/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log(id);
            const filter = { _id: new ObjectId(id) }
            console.log(filter);
            const updateDoc = {
                $set: {
                    role: "moderator"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log(result);
            res.send(result)
        })
        app.patch("/users/user/:id", verifyToken, async (req, res) => {
            const id = req.params.id;
            const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "user" } }
            );
            res.send(result);
        });

        const verifySeller = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isSeller = user?.role === "seller";
            if (isSeller) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next()
        }
        app.get('/users/seller/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' });
            }

            const user = await usersCollection.findOne({ email });
            const isSeller = user?.role === 'seller';
            res.send({ seller: isSeller });
        });

        app.patch("/users/seller/:id", verifyToken,async (req, res) => {
            const id = req.params.id;
            console.log("seller id", id);
            const filter = { _id: new ObjectId(id) }
            console.log("seller", filter);
            const updateDoc = {
                $set: {
                    role: "seller"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log("seller result", result);
            res.send(result)
        })


        /// Restaurant info 
        app.get("/sellerProfile", async (req, res) => {
            const result = await sellerProfileCollection.find().toArray();
            res.send(result)
        })


        app.post("/sellerProfile", verifyToken, async (req, res) => {
            const shoppingCart = req.body;
            const result = await sellerProfileCollection.insertOne(shoppingCart);
            console.log(result);
            res.send(result);
        })

        app.get("/sellerProfile/:shopName", async (req, res) => {
            const shopName = req.params.shopName;
            const query = { shopName: shopName };
            const result = await sellerProfileCollection.findOne(query);
            res.send(result)
        })
        app.get("/sellerProfile/:districtName", async (req, res) => {
            const districtName = req.params.districtName;
            const query = { districtName: districtName };
            const result = await sellerProfileCollection.find(query).toArray();
            console.log(result);
            res.send(result);
        })
        app.get("/sellerProfile/:shopName", async (req, res) => {
            const shopName = req.params.shopName;
            const query = { shopName: shopName };
            const result = await sellerProfileCollection.findOne(query);
            res.send(result);
        });

        app.get("/sellerProfile/district/:districtName", async (req, res) => {
            const districtName = req.params.districtName;
            const query = { districtName: districtName };
            const result = await sellerProfileCollection.find(query).toArray();
            console.log(result);
            res.send(result);
        });

        app.delete("/sellerProfile/:shopName", async (req, res) => {
            const shopName = req.params.shopName;
            const query = { shopName: shopName }
            const result = await sellerProfileCollection.deleteOne(query);
            res.send(result);
        })
        app.delete("/sellerProfile/:shopName/:productName", async (req, res) => {
            const { shopName, productName } = req.params;

            const filter = { shopName: shopName };
            const update = { $pull: { products: { productName: productName } } }; // Remove only the matching food

            const result = await sellerProfileCollection.updateOne(filter, update);

            if (result.modifiedCount > 0) {
                res.send({ success: true, message: "Food item deleted successfully" });
            } else {
                res.status(404).send({ success: false, message: "Food not found" });
            }
        });
        app.patch("/sellerProfile/:shopName", async (req, res) => {
            const shopName = req.params.shopName;
            const foodInfo = req.body;
            const query = { shopName };
            const updateDoc = {
                $push: { products: foodInfo }, // Push foodInfo into the "products" array
            };

            const result = await sellerProfileCollection.updateOne(query, updateDoc);
            res.send(result);
        });

        // products Related  api 
        app.get("/products", verifyToken, verifyAdmin, verifyModerator, verifySeller, async (req, res) => {
            const result = await productsCollection.find().toArray();
            res.send(result)
        })

        app.delete("/products/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await productsCollection.deleteOne(query);
            res.send(result)
        })

        // SSL Commerce Payment Intent
        app.post("/create-ssl-payment", async (req, res) => {

            const payment = req.body;
            console.log("Received Payment Data:", payment);

            const trxid = new ObjectId().toString();
            payment.transactionId = trxid;
            const initiatePayment = {
                store_id: process.env.SSL_COMMERCE_SECRET_ID,
                store_passwd: process.env.SSL_COMMERCE_SECRET_PASS,
                total_amount: parseFloat(payment.foodPrice),
                currency: "BDT",
                tran_id: trxid,
                success_url: "https://ShoppingGO-d3e1e.web.app/dashboard/paymentSuccess",
                fail_url: "http://localhost:5173/dashboard/fail",
                cancel_url: "http://localhost:5173/dashboard/cancel",
                ipn_url: "http://localhost:5173/dashboard/ipn-success-payment",
                shipping_method: "Courier",
                product_name: payment.productName || "Unknown",
                product_category: payment.category || "General",
                product_profile: "general",
                cus_name: payment.customerName || "Customer",
                cus_email: payment.email || "customer@example.com",
                cus_add1: payment.address || "Unknown Address",
                cus_city: payment.district || "Unknown City",
                cus_country: "Bangladesh",
                cus_phone: payment.contactNumber || "01700000000",
                ship_name: payment.customerName || "Customer",
                ship_add1: payment.address || "Unknown Address",
                ship_city: payment.district || "Unknown City",
                ship_country: "Bangladesh",
                ship_postcode: '4700'
            };

            console.log("Sending Payment Request:", initiatePayment);

            const inResponse = await axios.post(
                "https://sandbox.sslcommerz.com/gwprocess/v4/api.php",
                new URLSearchParams(initiatePayment).toString(), // Ensure correct encoding
                {
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                }
            );
            const saveData = await paymentCollection.insertOne(payment)
            const gatewayPageURL = inResponse?.data?.GatewayPageURL;
            res.send({ gatewayPageURL })


            // console.log(gatewayPageURL); 
        });
        app.post("/success-payment", async (req, res) => {
            try {
                const paymentSuccess = req.body;
                console.log(" Payment success data received:", paymentSuccess);

                const validationURL = `https://sandbox.sslcommerz.com/validator/api/validationserverAPI.php?val_id=${paymentSuccess.val_id}&store_id=foodh67aed7546ec54&store_passwd=foodh67aed7546ec54@ssl&format=json`;

                const { data } = await axios.get(validationURL);
                console.log("🔍 Validation response from SSLCommerz:", data);

                // Ensure payment is valid
                if (data.status !== "VALID" && data.status !== "VALIDATED") {
                    return res.send({ message: "Invalid Payment" });
                }

                // Check if the transaction exists in the database
                const payment = await paymentCollection.findOne({ transactionId: data.tran_id });

                if (!payment) {
                    return res.send({ message: "Transaction ID not found in database!" });
                }

                // Update payment status to "success"
                const updatePayment = await paymentCollection.updateOne(
                    { transactionId: data.tran_id },
                    { $set: { status: "success" } }
                );

                if (updatePayment.modifiedCount === 0) {
                    return res.send({ message: "Payment update failed!" });
                }

                console.log("✅ Payment status updated successfully!");
                const deletedResult = await shoppingCartCollection.deleteMany(query);
                // Redirect user to success page
                res.redirect("https://ShoppingGO-d3e1e.web.app/dashboard/paymentSuccess");
            } catch (error) {
                console.error(" Error in processing payment success:", error);
                res.status(500).send({ error: "Internal Server Error" });
            }
        });

        app.post('/create-payment-intent', async (req, res) => {
            try {
                const { price } = req.body;
                if (!price) {
                    return res.status(400).json({ error: "Price is required" });
                }
                const amount = parseInt(price * 100); // Convert to cents
                console.log("Creating PaymentIntent with amount:", amount);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount,
                    currency: "usd",
                    payment_method_types: ['card'],
                });

                console.log("Client Secret Sent:", paymentIntent.client_secret);
                res.json({ clientSecret: paymentIntent.client_secret });

            } catch (error) {
                console.error("Payment Intent Error:", error);
                res.status(500).json({ error: error.message });
            }
        });

        app.get("/payments/:email", async (req, res) => {
            const query = { email: req.params.email }
            // if (req.params.email !== req.decoded.email) {
            //   return res.status(403).send({ message: "forbidden access" })
            // }
            const result = await paymentCollection.find(query).toArray()
            res.send(result)
        })
        app.post("/payments", async (req, res) => {
            const payment = req.body;
            const paymentResult = await paymentCollection.insertOne(payment);
            const query = {
                _id: {
                    $in: payment.cartFoodId.map(id => new ObjectId(id))
                }
            };
            const deletedResult = await shoppingCartCollection.deleteMany(query);
            res.send({ paymentResult, deletedResult });

        });

        app.delete("/payments/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await paymentCollection.deleteOne(query)
            res.send(result)
        })

        // shoppingCart cart api 
        app.get("/shoppingCart", async (req, res) => {
            const email = req.query.email;
            const query = { email: email };
            const result = await shoppingCartCollection.find(query).toArray()
            res.send(result);
        })
        app.post("/shoppingCart", verifyToken, async (req, res) => {
            const foodInfo = req.body;
            const result = await shoppingCartCollection.insertOne(foodInfo);
            res.send(result)
        })
        app.patch("/shoppingCart/:id", async (req, res) => {
            const id = req.params.id;
            let { quantity } = req.body;

            try {
                // Parse and validate quantity
                quantity = parseInt(quantity);
                if (isNaN(quantity) || quantity < 1) {
                    quantity = 1; // Default to 1 if invalid or missing
                }

                const query = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: { quantity: quantity },
                    quantity: parseFloat(1)
                };

                const result = await shoppingCartCollection.updateOne(query, updateDoc);
                res.send(result);
            } catch (error) {
                console.error("Error updating quantity:", error);
                res.status(500).send({ error: "Failed to update quantity" });
            }
        });


        app.delete("/shoppingCart/:id", verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await shoppingCartCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })

        // DistrictAvailable api
        app.get("/districtAvailable", async (req, res) => {
            const result = await districtCollection.find().toArray();
            res.send(result);
        })

        app.post("/districtAvailable", verifyToken, verifyAdmin, async (req, res) => {
            const district = req.body;
            const result = await districtCollection.insertOne(district)
            res.send(result)
        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
    // Ensures that the client will close when you finish/error
 
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("ShoppingGO server is running")
})
app.listen(port, () => {
    console.log(`Signel crud server ${port}`);
})