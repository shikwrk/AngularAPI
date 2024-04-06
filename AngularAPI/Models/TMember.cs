using System;
using System.Collections.Generic;

namespace AngularAPI.Models;

public partial class TMember
{
    public int Id { get; set; }

    public string Name { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;
}
