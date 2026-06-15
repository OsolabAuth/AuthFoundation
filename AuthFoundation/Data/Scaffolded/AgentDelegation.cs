using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class AgentDelegation
{
    public string DelegationId { get; set; } = null!;

    public string AgentId { get; set; } = null!;

    public string OwnerOsolabId { get; set; } = null!;

    public string ClientId { get; set; } = null!;

    public string Scope { get; set; } = null!;

    public DateTime ExpiresDatetime { get; set; }

    public DateTime CreateDatetime { get; set; }

    public int Status { get; set; }
}
