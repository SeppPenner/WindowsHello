﻿using System;
using System.Runtime.Serialization;

namespace WindowsHello.Exceptions
{
    /// <summary>
    ///     The authentication provider invalid key exception.
    /// </summary>
    /// <seealso cref="AuthProviderException" />
    [Serializable]
    public class AuthProviderInvalidKeyException : AuthProviderException
    {
        /// <summary>Initializes a new instance of the <see cref="AuthProviderInvalidKeyException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        public AuthProviderInvalidKeyException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderInvalidKeyException"/> class.
        /// </summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="inner">The inner exception causing this exception.</param>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderInvalidKeyException(string message, Exception inner) : base(message, inner)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderInvalidKeyException" /> class.</summary>
        // ReSharper disable once UnusedMember.Global
        protected AuthProviderInvalidKeyException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderInvalidKeyException"/> class.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected AuthProviderInvalidKeyException(SerializationInfo info, StreamingContext context) : base(info,
            context)
        {
        }
    }
}