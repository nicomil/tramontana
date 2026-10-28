using Tramontana.Core;
using Tramontana.Modules.Apps;

namespace Tramontana.Modules;

/// <summary>Every file-cleaning module, by id.</summary>
public static class ModuleCatalog
{
    public static IReadOnlyList<ICleanerModule> All() =>
    [
        new SystemJunkModule(),
        new RecycleBinModule(),
        new LargeOldFilesModule(),
        new DuplicatesModule(),
        new SimilarImagesModule(),
        new InstallersModule(),
        new OrphansModule(),
        new RegistryModule(),
    ];

    public static ICleanerModule? Find(string id) =>
        All().FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));
}
