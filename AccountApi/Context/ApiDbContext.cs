using Microsoft.EntityFrameworkCore;

namespace AccountApi
{
    public class ApiDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options)
        {

        }
    }
}
