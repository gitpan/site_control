use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME                => 'Apache::SiteControl',
    VERSION_FROM        => 'SiteControl/AccessController.pm', # finds $VERSION
    PREREQ_PM           => {}, # e.g., Module::Name => 1.1
    ABSTRACT            => 'An object-oriented, fine-grained site access control facility',
    AUTHOR              => 'Tony Kay <tkay@uoregon.edu>',
);
