using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class Agent
{
    public string AgentId { get; set; } = null!;

    public string OwnerOsolabId { get; set; } = null!;

    public string AgentName { get; set; } = null!;

    public string SecretHash { get; set; } = null!;

    public string Status { get; set; } = null!;

    public DateTime? RevokedDatetime { get; set; }

    public DateTime CreateDatetime { get; set; }

    public DateTime UpdateDatetime { get; set; }
}
