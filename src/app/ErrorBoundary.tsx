import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "../design-system/components/Primitives";

export class RouteErrorBoundary extends Component<{ children: ReactNode; resetKey: string }, { error?: Error }> {
  state: { error?: Error } = {};

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    void fetch("/api/v2/client-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ level: "error", domain: "ti-scale-route", message: error.message, componentStack: info.componentStack }),
    }).catch(() => undefined);
  }

  componentDidUpdate(previous: Readonly<{ children: ReactNode; resetKey: string }>) {
    if (previous.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: undefined });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="os-page">
        <div className="os-route-error" role="alert">
          <p className="os-eyebrow">Route failure</p>
          <h1>This Ti-Scale surface could not render</h1>
          <p>{this.state.error.message}</p>
          <Button onClick={() => this.setState({ error: undefined })}>Try rendering again</Button>
        </div>
      </div>
    );
  }
}
