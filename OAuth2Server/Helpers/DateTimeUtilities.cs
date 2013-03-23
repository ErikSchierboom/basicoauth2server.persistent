namespace OAuth2Server.Helpers
{
    using System;

    /// <summary>
    /// A collection of utility methods dealing with dates and times.
    /// </summary>
    internal static class DateTimeUtilities
    {
        /// <summary>
        /// Ensures that local times are converted to UTC times.  Unspecified kinds are recast to UTC with no conversion.
        /// </summary>
        /// <param name="value">The date-time to convert.</param>
        /// <returns>The date-time in UTC time.</returns>
        internal static DateTime AsUtc(this DateTime value)
        {
            if (value.Kind == DateTimeKind.Unspecified)
            {
                return new DateTime(value.Ticks, DateTimeKind.Utc);
            }

            return value.ToUniversalTime();
        }

        /// <summary>
        /// Compares to string values for ordinal equality in such a way that its execution time does not depend on how much of the value matches.
        /// </summary>
        /// <param name="value1">The first value.</param>
        /// <param name="value2">The second value.</param>
        /// <returns>A value indicating whether the two strings share ordinal equality.</returns>
        /// <remarks>
        /// In signature equality checks, a difference in execution time based on how many initial characters match MAY
        /// be used as an attack to figure out the expected signature.  It is therefore important to make a signature
        /// equality check's execution time independent of how many characters match the expected value.
        /// See http://codahale.com/a-lesson-in-timing-attacks/ for more information.
        /// </remarks>
        internal static bool EqualsConstantTime(string value1, string value2)
        {
            // If exactly one value is null, they don't match.
            if (value1 == null ^ value2 == null)
            {
                return false;
            }

            // If both values are null (since if one is at this point then they both are), it's a match.
            if (value1 == null)
            {
                return true;
            }

            if (value1.Length != value2.Length)
            {
                return false;
            }

            // This looks like a pretty crazy way to compare values, but it provides a constant time equality check,
            // and is more resistant to compiler optimizations than simply setting a boolean flag and returning the boolean after the loop.
            int result = 0;
            for (int i = 0; i < value1.Length; i++)
            {
                result |= value1[i] ^ value2[i];
            }

            return result == 0;
        }
    }
}