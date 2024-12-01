import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
  try {
    // Get token from headers
    const token = req.headers["authorization"]?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ status: "failed", message: "Unauthorized: No token provided" });
    }

    // Verify token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ status: "failed", message: "Forbidden: Invalid token" });
      }

      // Attach user info to the request
      req.body.user = decoded;
      next();
    });
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ status: "failed", message: "Internal Server Error" });
  }
};

export default authMiddleware;
