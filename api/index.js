const Http = require("http");
const Express = require("express");
const { AuthArmorSDK } = require("autharmor-node-sdk");
const Dotenv = require("dotenv-safe");
const Cors = require("cors");
const bodyParser = require("body-parser");
const { generateAccessToken, verifyToken } = require("./utils/Tokens");

// Setup Env variables
Dotenv.config();

// Initialize Express app
const app = Express();
const Server = Http.createServer(app);

// Initialize AuthArmor SDK
const AuthArmor = new AuthArmorSDK({
  server: Server, // Enables Authentication through WebSockets
  clientId: process.env.CLIENT_ID, // AuthArmor API Client ID
  clientSecret: process.env.CLIENT_SECRET, // AuthArmor API Client Secret
  secret: process.env.SECRET, // Specify a Secret for the tokens that will be generated through the SDK
  webauthnClientId: "1bd515ee-c7d5-4e19-ba6e-348f9a785f19"
});

app.use(bodyParser.json());

app.use(
  Cors({
    origin: [
      "http://localhost:3000",
      "https://autharmor-demo.vercel.app",
      "https://autharmor-demo-static.herokuapp.com",
      "http://localhost:44403"
    ],
    credentials: true
  })
);

app.post("/enroll/webauthn/start", async (req, res) => {
  const { username, userId, timeout = 30000 } = req.body;
  console.log({
    username,
    userId
  });
  const startData = await AuthArmor.startEnrollCredentials({
    username,
    timeout
  });
  res.json(startData);
});

app.post("/enroll/webauthn/finish", async (req, res) => {
  const { username, userId, signedResponse } = req.body;
  const finishData = await AuthArmor.verifyEnrollCredentials({
    signedResponse,
    username,
    userId
  });
  res.json(finishData);
});

app.get("/me", verifyToken, async (req, res) => {
  // Return currently authenticated user
  res.json({
    user: {
      username: req.user.username,
      user_id: req.user.user_id
    }
  });
});

app.post("/users/:userId/validate", async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await AuthArmor.getUserById({
      userId
    });

    // TODO: Verify the user is a new one in the DB and not one that was registered already...

    res.json({ verified: true, user });
  } catch (err) {
    console.error(err);
    res.status(400).json(err);
  }
});

app.post("/auth/:type/validate", async (req, res) => {
  const { requestId, token } = req.body;
  const { type } = req.params;
  const payload = {
    type,
    requestId,
    token
  };

  try {
    const status = await AuthArmor.verifyAuthRequest(payload);

    console.log(status.requestDetails);

    res.json({
      verified: status.verified,
      requestDetails: status.requestDetails,
      token: generateAccessToken(status.requestDetails)
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ err, payload });
  }
});

// Register validation
app.post("/register/:type/validate", async (req, res) => {
  const { requestId, token } = req.body;
  const { type } = req.params;
  const payload = {
    type,
    requestId,
    token
  };

  try {
    const status = await AuthArmor.verifyRegisterRequest(payload);
    res.json({
      verified: status.verified,
      requestDetails: status.requestDetails,
      token: generateAccessToken(status.requestDetails)
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ err, payload });
  }
});

console.log(`🎉 Server is up and running at port ${process.env.PORT}!`);

Server.listen(process.env.PORT);
