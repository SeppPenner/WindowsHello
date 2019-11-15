﻿using System;
using System.Runtime.Serialization;

namespace WindowsHello.Exceptions
{
    /// <summary>
    ///     The windows hello exception.
    /// </summary>
    [Serializable]
    public class WindowsHelloException : Exception
    {
        /// <summary>Initializes a new instance of the <see cref="WindowsHelloException" /> class.</summary>
        // ReSharper disable once UnusedMember.Global
        public WindowsHelloException()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="WindowsHelloException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        public WindowsHelloException(string message) : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="WindowsHelloException" /> class.</summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="inner">The inner exception causing this exception.</param>
        public WindowsHelloException(string message, Exception inner) : base(message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsHelloException"/> class.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected WindowsHelloException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}