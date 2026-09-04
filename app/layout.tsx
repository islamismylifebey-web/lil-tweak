import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const viewport: Viewport = {
  colorScheme: "light",
  themeColor: "#146cff",
};

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "lil-tweak.chatgpt.site";
  const protocol =
    requestHeaders.get("x-forwarded-proto") ??
    (host.startsWith("localhost") || host.startsWith("127.0.0.1")
      ? "http"
      : "https");
  const origin = `${protocol}://${host}`;

  return {
    title: "Lil'Tweak.AI",
    description: "A quiet private workspace. Execution remains disconnected.",
    applicationName: "Lil'Tweak.AI",
    manifest: "/manifest.webmanifest?v=26",
    icons: {
      icon: [
        { url: "/favicon.ico?v=26", sizes: "any" },
        { url: "/icons/lil-tweak-192.png?v=26", sizes: "192x192", type: "image/png" },
        { url: "/icons/lil-tweak-512.png?v=26", sizes: "512x512", type: "image/png" },
      ],
      shortcut: [{ url: "/favicon.ico?v=26" }],
      apple: [{ url: "/apple-touch-icon.png?v=26", sizes: "180x180", type: "image/png" }],
    },
    robots: { index: false, follow: false, nocache: true },
    referrer: "no-referrer",
    openGraph: {
      type: "website",
      title: "Lil'Tweak.AI",
      description: "A quiet private workspace.",
      siteName: "Lil'Tweak.AI",
      url: origin,
    },
    twitter: {
      card: "summary",
      title: "Lil'Tweak.AI",
      description: "A quiet private workspace.",
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
