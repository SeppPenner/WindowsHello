using System;
using System.Runtime.Serialization;

namespace WindowsHello.Exceptions
{
    /// <summary>
    /// The authentication provider unavailable exception.
    /// </summary>
    /// <seealso cref="AuthProviderException" />
    [Serializable]
    public class AuthProviderIsUnavailableException : AuthProviderException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderIsUnavailableException() : this("Authentication provider is not available.")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
        /// </summary>
        /// <param name="message">The message describing the error.</param>
        public AuthProviderIsUnavailableException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
        /// </summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="inner">The inner exception causing this exception.</param>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderIsUnavailableException(string message, Exception inner) : base(message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected AuthProviderIsUnavailableException(SerializationInfo info, StreamingContext context) : base(info,
            context)
        {
        }
    }
}