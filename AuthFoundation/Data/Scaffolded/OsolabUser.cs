using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class OsolabUser
{
    public string OsolabId { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public string Nonce { get; set; } = null!;

    public DateTime CreateDatetime { get; set; }

    public DateTime UpdateDatetime { get; set; }

    public int Status { get; set; }
}
