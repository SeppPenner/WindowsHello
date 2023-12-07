// --------------------------------------------------------------------------------------------------------------------
// <copyright file="WindowsHelloException.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The windows hello exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
///     The windows hello exception.
/// </summary>
[Serializable]
public class WindowsHelloException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="WindowsHelloException" /> class.</summary>
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
}
