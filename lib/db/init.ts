import { VulnerabilityService } from '../services/vulnerability.service';
import { getDatabase } from '../mongodb';

export async function initializeDatabase() {
  try {
    console.log('Initializing database...');
    
    // Test database connection
    const db = await getDatabase();
    await db.command({ ping: 1 });
    console.log('✓ Database connection successful');

    // Create indexes
    await VulnerabilityService.initializeDatabase();
    console.log('✓ Database indexes created');

    // Get initial statistics
    const stats = await VulnerabilityService.getStatistics();
    console.log('✓ Database statistics:', stats);

    console.log('Database initialization completed successfully');
    return true;
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
}

export async function healthCheck(): Promise<{
  connected: boolean;
  database: string;
  collections: string[];
  error?: string;
}> {
  try {
    const db = await getDatabase();
    await db.command({ ping: 1 });
    
    const collections = await db.listCollections().toArray();
    
    return {
      connected: true,
      database: db.databaseName,
      collections: collections.map(c => c.name)
    };
  } catch (error) {
    return {
      connected: false,
      database: '',
      collections: [],
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}