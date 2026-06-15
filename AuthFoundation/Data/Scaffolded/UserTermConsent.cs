using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class UserTermConsent
{
    public long ConsentId { get; set; }

    public string OsolabId { get; set; } = null!;

    public string ClientId { get; set; } = null!;

    public string TermId { get; set; } = null!;

    public string TermVersion { get; set; } = null!;

    public bool ConsentResult { get; set; }

    public DateTime ConsentedDatetime { get; set; }

    public DateTime CreateDatetime { get; set; }
}
