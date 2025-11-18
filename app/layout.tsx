import type { Metadata } from "next";
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

export const metadata: Metadata = {
  metadataBase: new URL('https://secforit.ro'), // Update with your actual domain
  
  title: {
    default: "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring | SECFORIT",
    template: "%s | Zero-Day Tracker | SECFORIT"
  },
  
  description: "Professional zero-day vulnerability tracker providing real-time CVE monitoring from CISA Known Exploited Vulnerabilities (KEV) and National Vulnerability Database (NVD). Stay ahead of critical security threats with AI-powered analysis and instant alerts.",
  
  keywords: [
    "zero-day vulnerabilities",
    "CVE tracker",
    "CISA KEV",
    "National Vulnerability Database",
    "NVD",
    "cybersecurity monitoring",
    "vulnerability management",
    "security intelligence",
    "threat intelligence",
    "CVE monitoring",
    "security vulnerabilities",
    "exploit database",
    "vulnerability scanner",
    "security dashboard",
    "AI vulnerability analysis",
    "CVSS scoring",
    "security alerts",
    "patch management",
    "cyber threat intelligence",
    "SECFORIT"
  ],
  
  authors: [
    { 
      name: "Lisman Razvan",
      url: "https://secforit.ro"
    },
    {
      name: "SECFORIT SRL",
      url: "https://secforit.ro"
    }
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
    siteName: "Zero-Day Vulnerability Tracker",
    title: "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring",
    description: "Professional cybersecurity platform for tracking zero-day vulnerabilities and CVEs from CISA KEV and NVD with AI-powered threat analysis.",
    images: [
      {
        url: "/og-image.png", // Create this image (1200x630px)
        width: 1200,
        height: 630,
        alt: "Zero-Day Vulnerability Tracker Dashboard",
      }
    ],
  },
  
  twitter: {
    card: "summary_large_image",
    title: "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring",
    description: "Track critical vulnerabilities from CISA KEV and NVD with AI-powered analysis. Stay protected with real-time security intelligence.",
    creator: "@secforit", // Update with your Twitter handle
    images: ["/twitter-image.png"], // Create this image (1200x600px)
  },
  
  alternates: {
    canonical: "https://secforit.ro",
    languages: {
      'en-US': 'https://secforit.ro',
      'ro-RO': 'https://secforit.ro/ro', // If you add Romanian version
    },
  },
  
  category: "Cybersecurity",
  
  verification: {
    google: "your-google-verification-code", // Add after Google Search Console setup
    // yandex: "your-yandex-verification-code",
    // bing: "your-bing-verification-code",
  },
  
  other: {
    'application-name': 'Zero-Day Vulnerability Tracker',
    'apple-mobile-web-app-capable': 'yes',
    'apple-mobile-web-app-status-bar-style': 'default',
    'apple-mobile-web-app-title': 'ZeroDay Tracker',
    'format-detection': 'telephone=no',
    'mobile-web-app-capable': 'yes',
  }
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* Additional SEO meta tags */}
        <link rel="canonical" href="https://secforit.ro" />
        
        {/* Preconnect to external domains for performance */}
        <link rel="preconnect" href="https://www.cisa.gov" />
        <link rel="preconnect" href="https://services.nvd.nist.gov" />
        <link rel="dns-prefetch" href="https://www.cisa.gov" />
        <link rel="dns-prefetch" href="https://services.nvd.nist.gov" />
        
        {/* Favicons */}
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" href="/icon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/manifest.json" />
        
        {/* Theme color for mobile browsers */}
        <meta name="theme-color" content="#3b82f6" />
        <meta name="msapplication-TileColor" content="#3b82f6" />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}