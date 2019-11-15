using System;
using System.Runtime.Serialization;

namespace WindowsHello.Exceptions
{
    /// <summary>
    /// The authentication provider system error exception.
    /// </summary>
    /// <seealso cref="EnvironmentErrorException" />
    [Serializable]
    public class AuthProviderSystemErrorException : EnvironmentErrorException
    {
        /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderSystemErrorException()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="errorCode">The error code.</param>
        public AuthProviderSystemErrorException(string message, int errorCode) : base(message, errorCode)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderSystemErrorException(string message) : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="inner">The inner exception causing this exception.</param>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderSystemErrorException(string message, Exception inner) : base(message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderSystemErrorException"/> class.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected AuthProviderSystemErrorException(
            SerializationInfo info,
            StreamingContext context) : base(info, context)
        {
        }
    }
}