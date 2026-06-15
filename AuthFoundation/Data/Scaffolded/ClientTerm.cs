using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class ClientTerm
{
    public string ClientId { get; set; } = null!;

    public string TermId { get; set; } = null!;

    public bool Required { get; set; }

    public int DisplayOrder { get; set; }

    public DateTime CreateDatetime { get; set; }

    public DateTime UpdateDatetime { get; set; }

    public int Status { get; set; }
}
