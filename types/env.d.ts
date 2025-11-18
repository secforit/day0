declare global {
  namespace NodeJS {
    interface ProcessEnv {
      MONGODB_URI: string;
      MONGODB_DB_NAME?: string;
      GROQ_API_KEY: string;
      NEXT_PUBLIC_BASE_URL?: string;
      NODE_ENV: 'development' | 'production' | 'test';
    }
  }
}

export {};