import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

class Boundary extends React.Component {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <main className="loading">
        <h1>This view could not load.</h1>
        <p>Your saved work remains on the server. Refresh to reconnect.</p>
        <button className="button" onClick={() => window.location.reload()}>
          Reload workspace
        </button>
      </main>
    ) : (
      this.props.children
    );
  }
}
createRoot(document.getElementById("root")).render(
  <Boundary>
    <App />
  </Boundary>,
);
