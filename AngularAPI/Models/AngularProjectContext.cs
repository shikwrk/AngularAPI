using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace AngularAPI.Models;

public partial class AngularProjectContext : DbContext
{
    public AngularProjectContext()
    {
    }

    public AngularProjectContext(DbContextOptions<AngularProjectContext> options)
        : base(options)
    {
    }

    public virtual DbSet<TMember> TMembers { get; set; }

//    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
//#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
//        => optionsBuilder.UseSqlServer("Data Source=.;TrustServerCertificate=true;Initial Catalog=AngularProject;Integrated Security=true");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TMember>(entity =>
        {
            entity.ToTable("tMember");

            entity.Property(e => e.Name).HasMaxLength(50);
            entity.Property(e => e.Password).HasMaxLength(50);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
