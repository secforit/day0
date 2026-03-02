import type { Metadata, Viewport } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
});

export const metadata: Metadata = {
  metadataBase: new URL('https://secforit.ro'),
  title: {
    default: "SECFORIT ZeroDay | Real-Time CVE Monitoring Console",
    template: "%s | SECFORIT ZeroDay"
  },
  description: "Professional zero-day vulnerability tracker providing real-time CVE monitoring from CISA Known Exploited Vulnerabilities (KEV) and National Vulnerability Database (NVD). Stay ahead of critical security threats.",
  keywords: [
    "zero-day vulnerabilities", "CVE tracker", "CISA KEV",
    "National Vulnerability Database", "NVD", "cybersecurity monitoring",
    "vulnerability management", "security intelligence", "threat intelligence",
    "CVE monitoring", "CVSS scoring", "security dashboard", "SECFORIT"
  ],
  authors: [
    { name: "Lisman Razvan", url: "https://secforit.ro" },
    { name: "SECFORIT SRL", url: "https://secforit.ro" }
  ],
  creator: "Lisman Razvan - SECFORIT SRL",
  publisher: "SECFORIT SRL",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://secforit.ro",
    siteName: "SECFORIT ZeroDay",
    title: "SECFORIT ZeroDay | Real-Time CVE Monitoring Console",
    description: "Professional cybersecurity platform for tracking zero-day vulnerabilities and CVEs from CISA KEV and NVD.",
  },
  twitter: {
    card: "summary_large_image",
    title: "SECFORIT ZeroDay | Real-Time CVE Monitoring",
    description: "Track critical vulnerabilities from CISA KEV and NVD with real-time security intelligence.",
  },
  alternates: {
    canonical: "https://secforit.ro",
  },
  category: "Cybersecurity",
};

export const viewport: Viewport = {
  themeColor: '#dc2626',
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://www.cisa.gov" />
        <link rel="preconnect" href="https://services.nvd.nist.gov" />
        <link rel="icon" href="/favicon.ico" sizes="32x32" />
        <link rel="icon" href="/icon-192.png" type="image/png" sizes="192x192" />
        <link rel="icon" href="/icon-512.png" type="image/png" sizes="512x512" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body className={`${spaceGrotesk.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        {children}
      </body>
    </html>
  );
}
