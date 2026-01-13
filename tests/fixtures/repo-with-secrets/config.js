// Configuration with hardcoded secrets (should be detected)

module.exports = {
    // AWS credentials
    aws: {
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },

    // Database connection string
    database: {
        url: "mongodb://admin:secretpass@localhost:27017/mydb"
    },

    // API key
    apiKey: "sk_live_51H5YXH2xh9H5YXH",

    // Stripe key
    stripeKey: "sk_test_51H5YXH2xh9H5YXH",

    // Google API key
    googleKey: "AIzaSyDa-1xh9H5YXH2xh9H5YXH2xh9H5YX",

    // Redis connection
    redis: {
        url: "redis://:mysecretpassword@localhost:6379"
    },

    // Good practice - using environment variables (safe)
    safeConfig: {
        apiKey: process.env.API_KEY,
        databaseUrl: process.env.DATABASE_URL
    }
};
