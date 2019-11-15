﻿using System;
using System.Runtime.Serialization;

namespace WindowsHello.Exceptions
{
    /// <summary>
    /// The authentication provider system error exception.
    /// </summary>
    /// <seealso cref="AuthProviderException" />
    [Serializable]
    public class AuthProviderUserCancelledException : AuthProviderException
    {
        /// <summary>Initializes a new instance of the <see cref="AuthProviderUserCancelledException" /> class.</summary>
        public AuthProviderUserCancelledException() : this("Operation was canceled by user.")
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderUserCancelledException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        public AuthProviderUserCancelledException(string message) : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="AuthProviderException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="inner">The inner exception causing this exception.</param>
        // ReSharper disable once UnusedMember.Global
        public AuthProviderUserCancelledException(string message, Exception inner) : base(message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthProviderException"/> class.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected AuthProviderUserCancelledException(SerializationInfo info, StreamingContext context) : base(info,
            context)
        {
        }
    }
}