export function ProviderTabs({ active }: { active: "oidc" | "saml" }) {
  return (
    <nav className="provider-tabs" aria-label="Provider protocol">
      <a
        href="/providers"
        aria-current={active === "oidc" ? "page" : undefined}
      >
        OpenID Connect
      </a>
      <a
        href="/saml-providers"
        aria-current={active === "saml" ? "page" : undefined}
      >
        SAML
      </a>
    </nav>
  );
}
