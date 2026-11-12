import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import DesktopApp from "./desktop/DesktopApp";

createRoot(document.getElementById("root")).render(<React.StrictMode><DesktopApp /></React.StrictMode>);
