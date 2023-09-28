import { Profile } from "@workos-inc/node";

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

  /**
   * Similar to `findByEmail`, this doesn't actually perform any lookups. Actual
   * production applications should make sure to use a combination of the `profile.id`
   * and `profile.organizationId` to ensure lookups are scoped to the correct tenant.
   */
  findByProfile(profile: Profile): User {
    return { email: profile.email };
  }
}
