import { createRoot } from "react-dom/client";
import { App } from "./app";
import { Invite } from "./invite";
import { takeInvitation } from "./invitation-safety";
import "./styles.css";

const root = createRoot(document.getElementById("root")!);
let invitationGeneration = 0;
function renderInvitation() {
  let token = takeInvitation(window.location, window.history);
  const takeToken = () => {
    const result = token;
    token = null;
    return result;
  };
  root.render(<Invite key={++invitationGeneration} takeToken={takeToken} />);
}
if (window.location.pathname === "/invite") {
  renderInvitation();
  // Reopening a link in this tab may navigate only its fragment.
  window.addEventListener("hashchange", () => {
    if (window.location.pathname === "/invite" && window.location.hash)
      renderInvitation();
  });
} else root.render(<App />);
