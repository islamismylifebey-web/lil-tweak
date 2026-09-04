import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Lil'Tweak.AI",
    short_name: "Lil'Tweak.AI",
    description: "Owner-controlled AI engineering workbench.",
    id: "/?pwa=lil-tweak-v26",
    start_url: "/?pwa=lil-tweak-v26",
    scope: "/",
    display: "standalone",
    background_color: "#ffffff",
    theme_color: "#146cff",
    icons: [
      {
        src: "/icons/lil-tweak-192.png?v=26",
        sizes: "192x192",
        type: "image/png",
        purpose: "any",
      },
      {
        src: "/icons/lil-tweak-512.png?v=26",
        sizes: "512x512",
        type: "image/png",
        purpose: "any",
      },
      {
        src: "/icons/lil-tweak-maskable-192.png?v=26",
        sizes: "192x192",
        type: "image/png",
        purpose: "maskable",
      },
      {
        src: "/icons/lil-tweak-maskable-512.png?v=26",
        sizes: "512x512",
        type: "image/png",
        purpose: "maskable",
      },
    ],
  };
}
