using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class UserInfo
{
    public string OsolabId { get; set; } = null!;

    public string ClientId { get; set; } = null!;

    public string DataKey { get; set; } = null!;

    public string DataValue { get; set; } = null!;

    public DateTime CreateDatetime { get; set; }

    public DateTime UpdateDatetime { get; set; }

    public int Status { get; set; }
}
