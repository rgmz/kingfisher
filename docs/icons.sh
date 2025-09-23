# Create a local icon dir
mkdir -p icons

# Simple Icons (CDN source is stable and permissively licensed)
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/github.svg       -o icons/github.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/gitlab.svg       -o icons/gitlab.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/bitbucket.svg    -o icons/bitbucket.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/gitea.svg        -o icons/gitea.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/slack.svg        -o icons/slack.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/jirasoftware.svg -o icons/jira.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/confluence.svg   -o icons/confluence.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/amazonaws.svg    -o icons/aws.svg
curl -fsSL https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/docker.svg       -o icons/docker.svg

# A neutral folder + git icon from Octicons for files/dirs + local git repos
curl -fsSL https://raw.githubusercontent.com/primer/octicons/main/icons/file-directory-24.svg -o icons/folder.svg
curl -fsSL https://raw.githubusercontent.com/primer/octicons/main/icons/git-branch-24.svg     -o icons/git.svg
