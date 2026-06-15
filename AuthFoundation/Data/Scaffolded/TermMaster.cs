using System;
using System.Collections.Generic;

namespace AuthFoundation.Data.Scaffolded;

public partial class TermMaster
{
    public string TermId { get; set; } = null!;

    public string TermType { get; set; } = null!;

    public string Title { get; set; } = null!;

    public string Version { get; set; } = null!;

    public string Content { get; set; } = null!;

    public DateTime EffectiveStartDatetime { get; set; }

    public DateTime? EffectiveEndDatetime { get; set; }

    public DateTime CreateDatetime { get; set; }

    public DateTime UpdateDatetime { get; set; }

    public int Status { get; set; }
}
