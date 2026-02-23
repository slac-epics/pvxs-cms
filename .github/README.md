# CI matrix


| Platform      | EPICS Base Version  | authnstd | authnkrb | authnldap | pvxcert | pvacms | Tests |
|---------------|---------------------|----------|----------|-----------|---------|--------|-------|
| Linux (gcc)   | 7.0-secure-pvaccess | ✅        | ✅        | ✅         | ✅       | ✅      | ✅     |
| Linux (gcc)   | R7.0.2              | ✅        | ✅        | ✅         | ✅       | ✅      | ✅     |
| Linux (gcc)   | 3.15                | ✅        | ✅        | ✅         | ✅       | ✅      | ✅     |
| Linux (clang) | 7.0-secure-pvaccess | ✅        | ✅        | ✅         | ✅       | ✅      | ✅     |
| macOS         | 7.0-secure-pvaccess | ✅        | ✅        | ✅         | ✅       | ✅      | ✅     |
| Windows       | 7.0-secure-pvaccess | ✅        | ❌        | ❌         | ✅       | ❌      | ✅     |
| RTEMS         | 7.0-secure-pvaccess | ✅        | ❌        | ❌         | ✅       | ❌      | ✅     |
| mingw         | 7.0-secure-pvaccess | ✅        | ✅        | ❌         | ✅       | ❌      | ✅     |

