import type { SVGProps } from "react";
import type { NavIconName } from "../../app/router/routes";

const paths: Record<NavIconName, string[]> = {
  overview: ["M4 4h6v6H4z", "M14 4h6v4h-6z", "M14 12h6v8h-6z", "M4 14h6v6H4z"],
  missions: ["M5 4h14v16H5z", "M8 8h8", "M8 12h8", "M8 16h5"],
  live: ["M3 12h3l2-5 4 10 3-7 2 2h4"],
  guided: ["M5 5h14v11H9l-4 4z", "M9 9h6", "M9 12h4"],
  decisions: ["M12 3v18", "M5 7h14", "M7 7l-3 6h6z", "M17 7l-3 6h6z"],
  intelligence: ["M4 19l5-5 4 3 7-9", "M16 8h4v4", "M4 5h7"],
  agents: ["M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6", "M16 12a3 3 0 1 0 0-6", "M3 20c0-4 2-6 5-6s5 2 5 6", "M13 15c4-1 7 1 8 5"],
  brain: ["M9 4a3 3 0 0 0-3 3v1a3 3 0 0 0-1 5 3 3 0 0 0 2 5h2", "M15 4a3 3 0 0 1 3 3v1a3 3 0 0 1 1 5 3 3 0 0 1-2 5h-2", "M9 4v16", "M15 4v16", "M9 9h6", "M9 15h6"],
  learning: ["M4 5h16v13H4z", "M8 9h8", "M8 13h5"],
  observability: ["M3 12s3-6 9-6 9 6 9 6-3 6-9 6-9-6-9-6z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6"],
  reports: ["M6 3h9l4 4v14H6z", "M15 3v5h4", "M9 12h6", "M9 16h6"],
  system: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8", "M12 2v3", "M12 19v3", "M2 12h3", "M19 12h3", "M5 5l2 2", "M17 17l2 2", "M19 5l-2 2", "M7 17l-2 2"],
  manual: ["M5 4h5a3 3 0 0 1 3 3v13H8a3 3 0 0 0-3 1z", "M19 4h-5a3 3 0 0 0-3 3v13h5a3 3 0 0 1 3 1z", "M8 8h2", "M14 8h2"],
};

export function Icon({ name, ...props }: SVGProps<SVGSVGElement> & { name: NavIconName }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" {...props}>
      {paths[name].map((path) => <path key={path} d={path} />)}
    </svg>
  );
}
