# Clean up the VCPKG work trees to keep the docker image small
# (and reduce codebuild bootstrap time)

# Note that docker does not let us add files from higher directories,
# so this is copied into each variant directory

$tempdirs = @("c:\vcpkg\downloads", "c:\vcpkg\buildtrees")

$tempdirs | ForEach-Object {
    if (Test-Path -Path $_) {
        Remove-Item $_ -Recurse
    }
}

