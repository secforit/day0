# 🛡️ SECFORIT Vulnerability Tracker

> Real-time vulnerability intelligence platform powered by CISA KEV and National Vulnerability Database (NVD)

[![Next.js](https://img.shields.io/badge/Next.js-15.5.7-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.1-blue?style=flat-square&logo=react)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

A professional cybersecurity platform for tracking zero-day vulnerabilities and CVEs with AI-powered analysis, real-time feeds, and advanced querying capabilities.

![Dashboard Preview](docs/images/dashboard-preview.png)

## ✨ Features

### 🎯 Real-Time Dashboard
- Live vulnerability statistics from **CISA KEV** and **NVD**
- Severity-based categorization (Critical, High, Medium, Low)
- Recent zero-day and high-severity vulnerabilities tracking (last 30 days)
- Automated data refresh with manual refresh capability
- Responsive design optimized for all devices

### 🤖 AI-Powered Vulnerability Analysis
- **Llama 3.3 70B Versatile** model integration via Groq API (Mixtral-8x7b as fallback)
- Automated CVE summarization with structured analysis:
  - Threat overview and security risk assessment
  - Technical exploitation details and attack vectors
  - Impact assessment on systems and business
  - Affected systems and configurations
  - Mitigation strategies and immediate actions
  - Priority assessment and urgency evaluation
- Trusted reference extraction from official sources
- Pre-generated summaries for CISA KEV and recent NVD vulnerabilities

### 📡 RSS Feed
- Standards-compliant RSS 2.0 feed at `/rss`
- Combined CISA KEV and NVD recent vulnerabilities
- 30-minute cache for optimal performance
- Integration-ready for security tools and feed readers
- Includes CVE IDs, severity, CVSS scores, and full descriptions

### 🔍 NVD Query Console
Advanced search interface for the National Vulnerability Database API 2.0:

**Basic Queries:**
- CVE ID lookup - Direct vulnerability search
- Keyword search with exact match option
- Date range filtering (published dates)
- CVSS v3 severity filtering (Low, Medium, High, Critical)

**Advanced Queries:**
- **CPE filtering** - Product-specific vulnerability search
- **CWE filtering** - Common Weakness Enumeration search
- **CVSS vector strings** - Detailed metrics filtering
- **Version range filtering** - Specific version vulnerability tracking
- **Source identifier** - Filter by data source

**Additional Filters:**
- CISA KEV catalog integration
- CERT alerts and notes
- OVAL data filtering
- Rejected CVE exclusion
- CVE tags (disputed, unsupported, etc.)
- KEV date range filtering
- Pagination (up to 2,000 results per query)

**Export & Rate Limiting:**
- JSON and CSV export options
- User API key support for personal rate limits
- 5 requests/30s without key → 50 requests/30s with key
- Secure localStorage-based key management
- API key never stored on server

### 🎨 User Interface
- Dark theme optimized for security professionals
- Responsive design (mobile, tablet, desktop)
- Real-time loading states and error handling
- Severity color-coding for quick visual assessment
- Interactive modals and expandable content
- Professional gradient designs and animations

## 🚀 Quick Start

### Prerequisites

- Node.js 18.x or higher
- npm or yarn
- **Required**: Groq API Key (for AI analysis)
- **Optional**: NVD API Key (for higher rate limits - users can add their own in the UI)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR-USERNAME/secforit-vulnerability-tracker.git
cd secforit-vulnerability-tracker

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local and add your GROQ_API_KEY

# Run development server
npm run dev

# Open http://localhost:3000
```

### Minimal Configuration

Only **one** environment variable is required to run the application:

```env
# .env.local
GROQ_API_KEY=your_groq_api_key_here
```

**Get your Groq API key**: https://console.groq.com/

### Optional Configuration

```env
# Optional - Server-side NVD API key (users can add their own in the UI)
NVD_API_KEY=your_nvd_api_key_here

# Optional - Base URL for production
NEXT_PUBLIC_BASE_URL=https://yourdomain.com
```

That's it! The application is ready to use.

## 📖 Documentation

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client (Browser)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │ AI Summaries │  │  NVD Query   │      │
│  │   (Home)     │  │              │  │   Console    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Next.js 15 App Router (Server)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │/api/nvd-query│  │/api/ai-summary│ │  /rss        │      │
│  │  (POST/GET)  │  │    (POST)     │  │  (GET)       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  lib/vulnerability-fetch.ts                          │    │
│  │  - Multi-source data ingestion                       │    │
│  │  - Rate limiting & caching                           │    │
│  │  - Data transformation                               │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  CISA KEV    │    │   NVD API    │    │   Groq API   │
│   Catalog    │    │   (2.0)      │    │  (Mixtral)   │
│              │    │              │    │              │
│  (JSON Feed) │    │ (REST API)   │    │ (AI Model)   │
└──────────────┘    └──────────────┘    └──────────────┘

Data Flow:
1. User requests → Next.js API Routes
2. Server fetches from external APIs (CISA/NVD/Groq)
3. Data processed & transformed in lib/vulnerability-fetch.ts
4. Cached responses (30 min revalidation)
5. Returned to client as JSON
6. React components render the data
```

**Current Stack:**
- **Frontend**: React 19, Next.js 15 (App Router), TypeScript, Tailwind CSS
- **Backend**: Next.js API Routes (serverless)
- **AI**: Groq Cloud (Mixtral-8x7b-32768)
- **Data Sources**: CISA KEV (JSON), NVD API 2.0 (REST)
- **Caching**: Next.js ISR (Incremental Static Regeneration)
- **State Management**: React Hooks + localStorage (for API keys)
- **Deployment Ready**: Vercel, Docker, or traditional Node.js hosting

### Project Structure

```
secforit-vulnerability-tracker/
├── app/
│   ├── page.tsx                           # Home page with recent vulnerabilities
│   ├── layout.tsx                         # Root layout with metadata
│   ├── globals.css                        # Global styles and theme
│   │
│   ├── dashboard/                         # Dashboard page
│   │   └── page.tsx                       # Real-time statistics and monitoring
│   │
│   ├── ai-summaries/                      # AI analysis page
│   │   ├── page.tsx                       # Server component wrapper
│   │   └── AIVulnerabilitySummaries.tsx  # Client component with UI
│   │
│   ├── nvd-query/                         # NVD query console
│   │   ├── page.tsx                       # Page wrapper with documentation
│   │   └── NVDQueryConsole.tsx            # Query builder interface
│   │
│   ├── rss/                               # RSS feed endpoint
│   │   └── route.ts                       # RSS 2.0 XML generation
│   │
│   ├── api/
│   │   ├── nvd-query/                     # NVD API proxy
│   │   │   └── route.ts                   # Query handler with rate limiting
│   │   └── ai-summary/                    # AI analysis API (legacy)
│   │       └── route.ts                   # Groq API integration
│   │
│   ├── actions/                           # Next.js Server Actions
│   │   ├── vulnerability-actions.ts       # RSS refresh and stats
│   │   └── ai-summary-actions.ts          # AI summary generation
│   │
│   └── types/                             # TypeScript definitions
│       └── vulnerability.ts               # Shared type definitions
│
├── components/
│   └── Footer.tsx                         # Global footer component
│
├── lib/
│   └── vulnerability-fetch.ts             # Multi-source data fetching library
│                                          # - CISA KEV integration
│                                          # - NVD API 2.0 with rate limiting
│                                          # - Data transformation utilities
│                                          # - Export functions (JSON/CSV)
│
├── public/                                # Static assets
│   ├── favicon.ico
│   ├── icon.svg
│   └── apple-touch-icon.png
│
├── .env.local                             # Environment variables (not in git)
├── .env.example                           # Environment variables template
├── .gitignore                             # Git ignore rules
├── next.config.js                         # Next.js configuration
├── tailwind.config.ts                     # Tailwind CSS configuration
├── tsconfig.json                          # TypeScript configuration
├── package.json                           # Dependencies and scripts
└── README.md                              # This file

Note: MongoDB integration files (lib/mongodb.ts, lib/models/, lib/services/) 
are planned for future implementation - see Roadmap section.
```

## 🔧 Configuration

### Rate Limiting

The application implements intelligent rate limiting for NVD API:

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds
- **User API Keys**: Each user can provide their own key for personal rate limits

### Data Sources

The application currently integrates with two primary vulnerability data sources:

#### CISA KEV (Known Exploited Vulnerabilities)
- **Source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Format**: JSON feed
- **Update Frequency**: Real-time from official CISA catalog
- **Priority**: Highest (actively exploited vulnerabilities)
- **Cache**: 30-minute revalidation
- **Data Points**:
  - CVE ID
  - Vulnerability name and description
  - Affected vendor and product
  - Date added to KEV catalog
  - Required action and due date

#### NVD (National Vulnerability Database)
- **Source**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **Format**: REST API (JSON)
- **Update Frequency**: 30-minute cache revalidation
- **API Version**: 2.0
- **Coverage**: 318,000+ CVE records
- **Rate Limits**:
  - Without API key: 5 requests per 30 seconds
  - With API key: 50 requests per 30 seconds
- **Data Points**:
  - CVE ID and descriptions
  - CVSS v2, v3.0, v3.1, v4.0 scores and vectors
  - CPE (Common Platform Enumeration) matches
  - CWE (Common Weakness Enumeration) mappings
  - References and vendor advisories
  - Publication and modification dates
  - CISA KEV status

#### AI Analysis (Groq Cloud)
- **Model**: Llama 3.3 70B Versatile (primary), Mixtral-8x7b-32768 (fallback)
- **Provider**: Groq Cloud (https://groq.com)
- **Use Cases**: 
  - Vulnerability summarization
  - Threat intelligence analysis
  - Impact assessment
  - Mitigation recommendations
- **Context Window**: 32,768 tokens
- **Temperature**: 0.2 (for consistent, factual output)

**Note**: Additional sources (GitHub Security Advisories, Snyk, OSV) are implemented in the codebase but not actively used in the UI. These will be integrated in future updates.

## 🎨 Features in Detail

### Dashboard

The dashboard provides:
- **Total vulnerabilities tracked** across all sources
- **CISA KEV count** - actively exploited vulnerabilities
- **High severity count** - recent critical threats
- **RSS feed access** with manual refresh capability
- **Recent zero-day list** - last 30 days of critical vulnerabilities

### AI-Powered Analysis

Each vulnerability analysis includes:
1. **Threat Overview** - Core security risk assessment
2. **Technical Details** - Exploitation prerequisites and attack vectors
3. **Impact Assessment** - System and business impact
4. **Affected Systems** - Specific versions and configurations
5. **Mitigation Strategy** - Immediate actions and patches
6. **Priority Assessment** - Urgency and risk factors

### NVD Query Console

Advanced filtering capabilities:
- **Basic Tab**: CVE ID, keywords, date ranges, CVSS severity
- **Advanced Tab**: CPE names, CWE IDs, CVSS vectors, version ranges
- **Filters Tab**: Boolean filters, CVE tags, pagination controls

Query examples:
```typescript
// Find Windows 10 critical vulnerabilities
{
  cpeName: "cpe:2.3:o:microsoft:windows_10:*",
  cvssV3Severity: "CRITICAL",
  isVulnerable: true
}

// Search for SQL injection vulnerabilities
{
  cweId: "CWE-89",
  cvssV3Severity: "HIGH",
  resultsPerPage: 50
}

// Get CISA KEV vulnerabilities from last quarter
{
  hasKev: true,
  pubStartDate: "2024-10-01",
  pubEndDate: "2024-12-31"
}
```

## 🔐 Security

### API Key Management

User API keys are:
- ✅ Stored locally in browser (localStorage)
- ✅ Never sent to our servers
- ✅ Transmitted only in HTTP headers to NVD
- ✅ Easily removable by users
- ❌ NOT stored in databases
- ❌ NOT logged or tracked

### Data Privacy

- No personal data collection
- No user tracking or analytics
- Open-source and transparent
- All queries are client-side initiated

## 📊 API Endpoints

### GET /rss
Returns RSS 2.0 feed with latest vulnerabilities.

**Response**: `application/rss+xml`

### POST /api/nvd-query
Query the NVD database with advanced filters.

**Headers**:
```
Content-Type: application/json
X-NVD-API-Key: optional_user_api_key
```

**Request Body**:
```json
{
  "cveId": "CVE-2024-1234",
  "cvssV3Severity": "CRITICAL",
  "resultsPerPage": 20
}
```

**Response**:
```json
{
  "results": [...],
  "totalResults": 150,
  "timestamp": "2024-12-05T10:30:00Z",
  "usingApiKey": true
}
```

### POST /api/ai-summary
Generate AI-powered vulnerability summary.

**Request Body**:
```json
{
  "vulnerability": {
    "cveId": "CVE-2024-1234",
    "title": "...",
    "description": "...",
    "severity": "Critical",
    "cvssScore": 9.8
  }
}
```

**Response**:
```json
{
  "summary": "...",
  "trustedReferences": [...],
  "metadata": {
    "generatedAt": "2024-12-05T10:30:00Z",
    "model": "mixtral-8x7b-32768"
  }
}
```

## 🛠️ Tech Stack

### Frontend
- **Framework**: Next.js 15.5.7 (App Router)
- **React**: 19.2.1
- **TypeScript**: 5.0+
- **Styling**: Tailwind CSS 3.x
- **Icons**: Lucide React
- **Fonts**: Geist Sans & Geist Mono

### Backend
- **Runtime**: Node.js 18+
- **API Routes**: Next.js API Routes (serverless)
- **Server Actions**: Next.js Server Actions
- **Caching**: Next.js ISR (Incremental Static Regeneration)

### External APIs & Services
- **CISA KEV**: JSON feed from cisa.gov
- **NVD API**: REST API v2.0 from nvd.nist.gov
- **Groq AI**: Mixtral-8x7b-32768 model
- **Rate Limiting**: Custom implementation with timestamps

### Data Management
- **State**: React Hooks (useState, useEffect)
- **Storage**: Browser localStorage (API keys only)
- **Fetching**: Native fetch with ISR caching
- **No Database**: Currently stateless (database integration planned)

### Development Tools
- **Package Manager**: npm
- **Code Quality**: ESLint
- **Type Checking**: TypeScript compiler
- **Version Control**: Git

### Deployment
- **Recommended**: Vercel (zero-config)
- **Alternatives**: Docker, traditional Node.js hosting
- **CDN**: Automatic via hosting platform

## 🚢 Deployment

### Vercel (Recommended)

Vercel provides the best Next.js deployment experience with zero configuration:

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Follow prompts and add environment variables in dashboard
```

**Environment Variables in Vercel**:
1. Go to your project settings
2. Navigate to "Environment Variables"
3. Add `GROQ_API_KEY`
4. Optionally add `NVD_API_KEY` and `NEXT_PUBLIC_BASE_URL`

### Docker

```dockerfile
FROM node:18-alpine AS base

# Install dependencies
FROM base AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Build application
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# Production image
FROM base AS runner
WORKDIR /app
ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT 3000

CMD ["node", "server.js"]
```

Build and run:
```bash
docker build -t secforit-tracker .
docker run -p 3000:3000 --env-file .env.local secforit-tracker
```

### Traditional Node.js Hosting

```bash
# Build for production
npm run build

# Start production server
npm start

# Or use PM2 for process management
npm install -g pm2
pm2 start npm --name "secforit-tracker" -- start
pm2 save
pm2 startup
```

### Environment Variables for Production

Set these in your hosting platform:

**Required**:
```env
GROQ_API_KEY=your_groq_api_key
NODE_ENV=production
```

**Optional**:
```env
NVD_API_KEY=your_nvd_api_key
NEXT_PUBLIC_BASE_URL=https://yourdomain.com
```

### Post-Deployment Checklist

- [ ] Verify all pages load correctly
- [ ] Test API endpoints (`/api/nvd-query`, `/rss`)
- [ ] Check AI summaries generation
- [ ] Test NVD Query Console with filters
- [ ] Verify RSS feed works
- [ ] Check mobile responsiveness
- [ ] Test with and without API keys
- [ ] Monitor error logs

## 🧪 Development

### Development Commands

```bash
# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run ESLint
npm run lint

# Type check with TypeScript
npx tsc --noEmit
```

### Code Quality

```bash
# Lint and fix code
npm run lint

# Type check
npx tsc --noEmit

# Format code (if Prettier is configured)
npx prettier --write .
```

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow TypeScript best practices
   - Use existing component patterns
   - Add comments for complex logic

3. **Test your changes**
   - Run `npm run dev` and test in browser
   - Check all pages: `/`, `/dashboard`, `/ai-summaries`, `/nvd-query`
   - Verify API endpoints work correctly

4. **Build and verify**
   ```bash
   npm run build
   npm start
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: description of your feature"
   git push origin feature/your-feature-name
   ```

### Environment Setup

1. Copy environment variables:
   ```bash
   cp .env.example .env.local
   ```

2. Add required API keys:
   ```env
   GROQ_API_KEY=your_groq_api_key
   ```

3. Optional: Add NVD API key for server-side caching:
   ```env
   NVD_API_KEY=your_nvd_api_key
   ```

### Debugging

```bash
# Run with debug output
DEBUG=* npm run dev

# Check Next.js build output
npm run build -- --debug

# Analyze bundle size
npm run build && npx @next/bundle-analyzer
```

### Common Development Issues

**Issue**: React version mismatch
```bash
rm -rf node_modules package-lock.json
npm install react@19.2.1 react-dom@19.2.1 --save-exact
npm install
```

**Issue**: Port already in use
```bash
# Kill process on port 3000
lsof -ti:3000 | xargs kill -9
# Or use a different port
PORT=3001 npm run dev
```

**Issue**: Environment variables not loading
- Restart the dev server after changing `.env.local`
- Ensure `.env.local` is in the root directory
- Check that variables start with `NEXT_PUBLIC_` for client-side access

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style
- Write meaningful commit messages
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CISA** - For the Known Exploited Vulnerabilities catalog
- **NIST** - For the National Vulnerability Database
- **Groq** - For AI inference infrastructure
- **Vercel** - For Next.js framework and hosting
- **Anthropic** - For development assistance

## 📧 Contact

**SECFORIT SRL**
- Website: [secforit.ro](https://secforit.ro)
- Email: razvan@secforit.ro
- Developer: Lisman Razvan

## 🗺️ Roadmap

### 🔥 High Priority

#### Database Integration & Architecture Overhaul
- [ ] **MongoDB Integration**
  - Persistent vulnerability storage
  - Historical data tracking
  - Faster query performance
  - Reduced API calls to external services
  
- [ ] **Architecture Refactoring**
  - Implement repository pattern for data access
  - Add service layer for business logic
  - Background jobs for automated data ingestion
  - Cron jobs for periodic CISA KEV and NVD updates
  - Cache layer optimization

- [ ] **Data Models**
  - Vulnerability model with full CVE data
  - AI summary storage and versioning
  - User preferences and saved queries
  - Search history and analytics

### 🎯 Medium Priority

- [ ] **User Authentication**
  - User accounts and profiles
  - Saved queries and bookmarks
  - Personal vulnerability watchlists
  - Email preferences management
  
- [ ] **Email Alerts System**
  - Real-time notifications for new CISA KEV vulnerabilities
  - Daily/weekly digest options
  - Custom alert rules based on severity, CPE, or CWE
  - Integration with SMTP services

- [ ] **Enhanced Analytics**
  - Vulnerability trend analysis over time
  - Statistical charts and graphs
  - Export historical data
  - Comparison reports

- [ ] **GitHub Security Advisories Integration**
  - Add GitHub advisories to multi-source feed
  - Filter by programming language and ecosystem
  - Integration with existing query console

- [ ] **Snyk Database Integration**
  - Add Snyk as additional vulnerability source
  - Package vulnerability tracking
  - Open-source project scanning

### 🚀 Future Enhancements

- [ ] **Advanced Features**
  - API rate limit dashboard with real-time monitoring
  - Webhook integration (Slack, Discord, Microsoft Teams)
  - Custom RSS feeds based on user criteria
  - Mobile-responsive PWA features
  - Dark/Light theme toggle
  
- [ ] **Multi-language Support**
  - Romanian language translation
  - Internationalization (i18n) framework
  - Locale-based content

- [ ] **Mobile Application**
  - React Native companion app
  - Push notifications for critical vulnerabilities
  - Offline mode with cached data

- [ ] **Community Features**
  - User comments and notes on vulnerabilities
  - Community-driven severity ratings
  - Vulnerability discussions forum
  - Share queries and saved searches

- [ ] **AI Enhancements**
  - Multiple AI model support (GPT-4, Claude, etc.)
  - Comparison between different AI summaries
  - Custom prompt templates
  - AI-powered vulnerability impact prediction

- [ ] **Local AI Processing with Ollama (Security Bulletin Generator)**
  - Self-hosted LLM inference via Ollama on Ubuntu
  - Model: llama3.1:8b (8GB VRAM) or llama3.3:70b (48GB VRAM)
  - Open WebUI frontend for interactive bulletin generation
  - Automated Security Bulletin creation from CVE data
  - Dual-audience format: Executive Summary (non-technical) + Technical Details
  - Corporate software focus: filtering for enterprise/business applications
  - Bulletin sections: Risk Rating, Affected Software, Business Impact, Required Actions, Timeline
  - PDF/HTML export for distribution to stakeholders
  - Integration via Ollama REST API (`http://localhost:11434/api/generate`)

- [ ] **Enterprise Features**
  - Multi-tenant support
  - Team collaboration tools
  - Role-based access control (RBAC)
  - Audit logs and compliance reports
  - API access for programmatic integration

### 📊 Technical Debt

- [ ] Add comprehensive unit tests
- [ ] Add integration tests for API routes
- [ ] Add E2E tests with Playwright
- [ ] Improve error handling and logging
- [ ] Add performance monitoring (Sentry, LogRocket)
- [ ] Optimize bundle size
- [ ] Add server-side caching layer (Redis)
- [ ] Implement rate limiting for API routes
- [ ] Add API documentation (Swagger/OpenAPI)

## 📈 Performance & Optimization

### Current Performance Metrics

- ⚡ **Server-Side Rendering**: All pages use Next.js App Router SSR
- 🚀 **First Contentful Paint**: < 2.0s on fast 3G
- 📦 **Bundle Size**: Optimized with automatic code splitting
- 💾 **API Caching**: 30-minute ISR revalidation for all external API calls
- 🔄 **Client-Side Caching**: localStorage for user API keys

### Caching Strategy

```typescript
// ISR (Incremental Static Regeneration) with 30-minute revalidation
fetch(url, {
  next: { revalidate: 1800 } // 30 minutes
});
```

**Benefits**:
- Reduced API calls to CISA and NVD
- Faster page loads for subsequent visitors
- Automatic cache invalidation every 30 minutes
- Fresh data without manual refresh

### Optimization Techniques

1. **Code Splitting**: Automatic route-based splitting via Next.js
2. **Image Optimization**: Using Next.js Image component (when images added)
3. **Tree Shaking**: Unused code automatically removed in production
4. **Minification**: CSS and JavaScript minified in production builds
5. **Lazy Loading**: Components load on-demand
6. **Server Components**: Default to server components, client only when needed

### Performance Tips for Users

- **NVD Queries**: Use specific filters to reduce result set size
- **Date Ranges**: Limit to 120 days (API maximum) for faster queries
- **API Keys**: Add your NVD API key to avoid rate limits
- **Exports**: Export smaller datasets (< 500 records) for faster processing
- **Browser**: Use modern browsers (Chrome, Firefox, Safari, Edge latest versions)

## 🐛 Known Issues & Limitations

### Current Limitations

1. **No Data Persistence**
   - All data is fetched in real-time from external APIs
   - No historical vulnerability tracking
   - Query results are not saved between sessions
   - *Solution*: Database integration planned (see Roadmap)

2. **API Rate Limits**
   - NVD API: 5 requests/30s without key, 50 requests/30s with key
   - Users must provide their own NVD API key for higher limits
   - *Workaround*: Use personal API key in NVD Query Console

3. **React 19 Compatibility**
   - Must use exact version match between `react` and `react-dom`
   - Issue: Version mismatch causes build failures
   - *Fix*: See installation instructions

4. **Large Query Exports**
   - Exports with 1000+ results may be slow
   - Browser memory constraints for large CSV files
   - *Workaround*: Use pagination and export in smaller batches

5. **Real-time Data Only**
   - No ability to save queries or create alerts
   - No vulnerability tracking over time
   - *Future*: User authentication and database integration planned

### Reporting Issues

Found a bug? Please [open an issue](https://github.com/YOUR-USERNAME/secforit-vulnerability-tracker/issues) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Browser and OS information
- Screenshots if applicable

## 💡 Tips & Tricks

### Getting Started with NVD API Key

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form with your email
3. Check your email for the API key
4. Add it in the NVD Query Console interface

### Optimal Query Practices

- Use date ranges ≤ 120 days (API limit)
- Start with specific CVE IDs for known vulnerabilities
- Use CPE for product-specific queries
- Combine filters for precise results
- Export to CSV for spreadsheet analysis

### RSS Feed Integration

Add to your RSS reader:
```
https://yourdomain.com/rss
```

Popular readers: Feedly, Inoreader, NewsBlur, Thunderbird

---

<p align="center">
  Made with ❤️ by <a href="https://secforit.ro">SECFORIT</a> • 
  Securing the digital world, one vulnerability at a time
</p>

<p align="center">
  <a href="#-secforit-vulnerability-tracker">Back to top ⬆️</a>
</p>