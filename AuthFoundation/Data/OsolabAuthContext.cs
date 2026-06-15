using System;
using System.Collections.Generic;
using AuthFoundation.Data.Scaffolded;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Data;

public partial class OsolabAuthContext : DbContext
{
    public OsolabAuthContext(DbContextOptions<OsolabAuthContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Agent> Agents { get; set; }

    public virtual DbSet<AgentDelegation> AgentDelegations { get; set; }

    public virtual DbSet<ClientTerm> ClientTerms { get; set; }

    public virtual DbSet<OsolabUser> OsolabUsers { get; set; }

    public virtual DbSet<TermMaster> TermMasters { get; set; }

    public virtual DbSet<UserInfo> UserInfos { get; set; }

    public virtual DbSet<UserTermConsent> UserTermConsents { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Agent>(entity =>
        {
            entity.ToTable("agent", "auth");

            entity.HasIndex(e => new { e.OwnerOsolabId, e.Status }, "IX_agent_owner_active");

            entity.Property(e => e.AgentId)
                .HasMaxLength(64)
                .HasColumnName("agent_id");
            entity.Property(e => e.AgentName)
                .HasMaxLength(100)
                .HasColumnName("agent_name");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_agent_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.OwnerOsolabId)
                .HasMaxLength(16)
                .HasColumnName("owner_osolab_id");
            entity.Property(e => e.RevokedDatetime).HasColumnName("revoked_datetime");
            entity.Property(e => e.SecretHash).HasColumnName("secret_hash");
            entity.Property(e => e.Status)
                .HasMaxLength(20)
                .HasDefaultValue("active", "DF_agent_status")
                .HasColumnName("status");
            entity.Property(e => e.UpdateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_agent_update_datetime")
                .HasColumnName("update_datetime");
        });

        modelBuilder.Entity<AgentDelegation>(entity =>
        {
            entity.HasKey(e => e.DelegationId);

            entity.ToTable("agent_delegation", "auth");

            entity.HasIndex(e => new { e.AgentId, e.ClientId, e.Status, e.ExpiresDatetime }, "IX_agent_delegation_token_lookup");

            entity.Property(e => e.DelegationId)
                .HasMaxLength(64)
                .HasColumnName("delegation_id");
            entity.Property(e => e.AgentId)
                .HasMaxLength(64)
                .HasColumnName("agent_id");
            entity.Property(e => e.ClientId)
                .HasMaxLength(32)
                .HasColumnName("client_id");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_agent_delegation_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.ExpiresDatetime).HasColumnName("expires_datetime");
            entity.Property(e => e.OwnerOsolabId)
                .HasMaxLength(16)
                .HasColumnName("owner_osolab_id");
            entity.Property(e => e.Scope)
                .HasMaxLength(500)
                .HasColumnName("scope");
            entity.Property(e => e.Status)
                .HasDefaultValue(1, "DF_agent_delegation_status")
                .HasColumnName("status");
        });

        modelBuilder.Entity<ClientTerm>(entity =>
        {
            entity.HasKey(e => new { e.ClientId, e.TermId });

            entity.ToTable("client_term", "auth");

            entity.Property(e => e.ClientId)
                .HasMaxLength(32)
                .HasColumnName("client_id");
            entity.Property(e => e.TermId)
                .HasMaxLength(100)
                .HasColumnName("term_id");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_client_term_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.DisplayOrder).HasColumnName("display_order");
            entity.Property(e => e.Required).HasColumnName("required");
            entity.Property(e => e.Status)
                .HasDefaultValue(1, "DF_client_term_status")
                .HasColumnName("status");
            entity.Property(e => e.UpdateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_client_term_update_datetime")
                .HasColumnName("update_datetime");
        });

        modelBuilder.Entity<OsolabUser>(entity =>
        {
            entity.HasKey(e => e.OsolabId);

            entity.ToTable("osolab_user", "auth");

            entity.HasIndex(e => e.Email, "UX_osolab_user_email_active")
                .IsUnique()
                .HasFilter("([status]=(1))");

            entity.Property(e => e.OsolabId)
                .HasMaxLength(16)
                .HasColumnName("osolab_id");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_osolab_user_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.Email)
                .HasMaxLength(320)
                .HasColumnName("email");
            entity.Property(e => e.Nonce)
                .HasMaxLength(64)
                .HasColumnName("nonce");
            entity.Property(e => e.Password).HasColumnName("password");
            entity.Property(e => e.Status)
                .HasDefaultValue(1, "DF_osolab_user_status")
                .HasColumnName("status");
            entity.Property(e => e.UpdateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_osolab_user_update_datetime")
                .HasColumnName("update_datetime");
        });

        modelBuilder.Entity<TermMaster>(entity =>
        {
            entity.HasKey(e => e.TermId);

            entity.ToTable("term_master", "auth");

            entity.Property(e => e.TermId)
                .HasMaxLength(100)
                .HasColumnName("term_id");
            entity.Property(e => e.Content).HasColumnName("content");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_term_master_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.EffectiveEndDatetime).HasColumnName("effective_end_datetime");
            entity.Property(e => e.EffectiveStartDatetime).HasColumnName("effective_start_datetime");
            entity.Property(e => e.Status)
                .HasDefaultValue(1, "DF_term_master_status")
                .HasColumnName("status");
            entity.Property(e => e.TermType)
                .HasMaxLength(50)
                .HasColumnName("term_type");
            entity.Property(e => e.Title)
                .HasMaxLength(200)
                .HasColumnName("title");
            entity.Property(e => e.UpdateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_term_master_update_datetime")
                .HasColumnName("update_datetime");
            entity.Property(e => e.Version)
                .HasMaxLength(50)
                .HasColumnName("version");
        });

        modelBuilder.Entity<UserInfo>(entity =>
        {
            entity.HasKey(e => new { e.OsolabId, e.ClientId, e.DataKey });

            entity.ToTable("user_info", "auth");

            entity.Property(e => e.OsolabId)
                .HasMaxLength(16)
                .HasColumnName("osolab_id");
            entity.Property(e => e.ClientId)
                .HasMaxLength(32)
                .HasColumnName("client_id");
            entity.Property(e => e.DataKey)
                .HasMaxLength(100)
                .HasColumnName("data_key");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_user_info_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.DataValue).HasColumnName("data_value");
            entity.Property(e => e.Status)
                .HasDefaultValue(1, "DF_user_info_status")
                .HasColumnName("status");
            entity.Property(e => e.UpdateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_user_info_update_datetime")
                .HasColumnName("update_datetime");
        });

        modelBuilder.Entity<UserTermConsent>(entity =>
        {
            entity.HasKey(e => e.ConsentId);

            entity.ToTable("user_term_consent", "auth");

            entity.Property(e => e.ConsentId).HasColumnName("consent_id");
            entity.Property(e => e.ClientId)
                .HasMaxLength(32)
                .HasColumnName("client_id");
            entity.Property(e => e.ConsentResult).HasColumnName("consent_result");
            entity.Property(e => e.ConsentedDatetime).HasColumnName("consented_datetime");
            entity.Property(e => e.CreateDatetime)
                .HasDefaultValueSql("(sysutcdatetime())", "DF_user_term_consent_create_datetime")
                .HasColumnName("create_datetime");
            entity.Property(e => e.OsolabId)
                .HasMaxLength(16)
                .HasColumnName("osolab_id");
            entity.Property(e => e.TermId)
                .HasMaxLength(100)
                .HasColumnName("term_id");
            entity.Property(e => e.TermVersion)
                .HasMaxLength(50)
                .HasColumnName("term_version");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
