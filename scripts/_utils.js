exports.requireEnv = (variables) => {
    require('dotenv').config();
    const env = {};
    for (const key of variables) {
        const value = process.env[key];
        if (typeof value !== "string") {
            throw new Error("Missing environment variable: " + key);
        }
        env[key] = value;
    }
    return env;
}

exports.run = (main) => {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
};

exports.sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));