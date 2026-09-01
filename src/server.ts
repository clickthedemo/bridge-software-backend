import { env } from "./config/index.js";
import { app } from "./app.js";

app.listen(env.API_PORT, () => {
    console.log(
        `BRIDGE API listening on ${env.API_URL}`
    );
});