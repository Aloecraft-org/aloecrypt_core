__VER_MAJ:=$(shell jq '.TECHNO_VERSION.major' .technoproj)
__VER_MIN:=$(shell jq '.TECHNO_VERSION.minor' .technoproj)
__VER_PAT:=$(shell jq '.TECHNO_VERSION.patch' .technoproj)
__VER_BLD:=$(shell jq '.TECHNO_VERSION.build' .technoproj)
__VERSION:=${__VER_MAJ}.${__VER_MIN}.${__VER_PAT}
__VERSION_FULL:=${__VERSION} build ${__VER_BLD}

inc_maj:
	tmp=$$(mktemp) && jq '.TECHNO_VERSION.major += 1' ${__TECHNO_PROJECT_FILE} > "$$tmp" && mv "$$tmp" ${__TECHNO_PROJECT_FILE}

inc_min:
	tmp=$$(mktemp) && jq '.TECHNO_VERSION.minor += 1' ${__TECHNO_PROJECT_FILE} > "$$tmp" && mv "$$tmp" ${__TECHNO_PROJECT_FILE}

inc_pat:
	tmp=$$(mktemp) && jq '.TECHNO_VERSION.patch += 1' ${__TECHNO_PROJECT_FILE} > "$$tmp" && mv "$$tmp" ${__TECHNO_PROJECT_FILE}

inc_build:
	tmp=$$(mktemp) && jq '.TECHNO_VERSION.build += 1' ${__TECHNO_PROJECT_FILE} > "$$tmp" && mv "$$tmp" ${__TECHNO_PROJECT_FILE}