import { env } from "./config/index.js";
import { app } from "./app.js";

const port = env.PORT ?? env.API_PORT;

app.listen(port, () => {
    console.log(
        `BRIDGE API listening on port ${port}`
    );
});
