import babel from "rollup-plugin-babel";
import pkg from "./package.json";

export default {
  input: "src/password.js",
  external: ["crypto"],
  output: [
    { file: pkg.main, format: "cjs" },
    { file: pkg.module, format: "es" }
  ],
  plugins: [
    babel({
      exclude: ["node_modules/**"]
    })
  ]
};
