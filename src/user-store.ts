export interface User {
  email: string;
}

/**
 * A stand-in for a persistence layer storing application users that
 * would exist in a real-world application.
 */
export class UserStore {
  /**
   * This always returns back a user whose email matches the one given
   * for demonstration purposes.
   */
  findByEmail(email: string): User {
    return { email };
  }
}
