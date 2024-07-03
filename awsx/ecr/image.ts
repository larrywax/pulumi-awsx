// Copyright 2016-2022, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as aws from "@pulumi/aws";
import * as docker from "@pulumi/docker-build";
import * as pulumi from "@pulumi/pulumi";
import * as schema from "../schema-types";
import * as utils from "../utils";

export class Image extends schema.Image {
  constructor(name: string, args: schema.ImageArgs, opts: pulumi.ComponentResourceOptions = {}) {
    super(name, args, opts);
    this.imageUri = pulumi.output(args).apply((args) => computeImageFromAsset(args, this));
  }
}

/** @internal */
export function computeImageFromAsset(
  args: pulumi.Unwrap<schema.ImageArgs>,
  parent: pulumi.Resource,
) {
  const { repositoryUrl, registryId: inputRegistryId, imageTag, ...dockerInputs } = args ?? {};

  const url = new URL("https://" + repositoryUrl); // Add protocol to help it parse
  const registryId = inputRegistryId ?? url.hostname.split(".")[0];

  pulumi.log.debug(`Building container image at '${JSON.stringify(dockerInputs)}'`, parent);

  const imageName = args.imageName
    ? args.imageName
    : imageTag
    ? imageTag
    : createUniqueImageName(dockerInputs);

  // Note: the tag, if provided, is included in the image name.
  const canonicalImageName = `${repositoryUrl}:${imageName}`;

  // If we haven't, build and push the local build context to the ECR repository.  Then return
  // the unique image name we pushed to.  The name will change if the image changes ensuring
  // the TaskDefinition get's replaced IFF the built image changes.

  const ecrCredentials = aws.ecr.getCredentialsOutput(
    { registryId: registryId },
    { parent, async: true },
  );

  const registryCredentials = ecrCredentials.authorizationToken.apply((authorizationToken) => {
    const decodedCredentials = Buffer.from(authorizationToken, "base64").toString();
    const [username, password] = decodedCredentials.split(":");
    if (!password || !username) {
      throw new Error("Invalid credentials");
    }
    return {
      address: ecrCredentials.proxyEndpoint,
      username: username,
      password: password,
    };
  });

  const dockerImageArgs: docker.ImageArgs = {
    tags: [canonicalImageName],
    buildArgs: dockerInputs.args,
    cacheFrom: dockerInputs.cacheFrom
      ? dockerInputs.cacheFrom.map((r) => {
          return { registry: { ref: r } };
        })
      : undefined,
    cacheTo: args.cacheTo
      ? args.cacheTo.map((r) => {
          return {
            registry: {
              ref: r,
            },
          };
        })
      : [{ inline: {} }],
    context: dockerInputs.context ? { location: dockerInputs.context } : undefined,
    dockerfile: { location: dockerInputs.dockerfile },
    platforms: dockerInputs.platform ? [dockerInputs.platform as docker.Platform] : [],
    target: dockerInputs.target,
    push: true,
    buildOnPreview: false,
    registries: [registryCredentials],
  };

  const image = new docker.Image(imageName, dockerImageArgs, { parent });

  image.ref.apply((ref: any) =>
    pulumi.log.debug(`    build complete: ${imageName} (${ref})`, parent),
  );

  return image.ref;
}

function createUniqueImageName(inputs: pulumi.Unwrap<schema.DockerBuildInputs>): string {
  const { context, dockerfile, args } = inputs ?? {};
  // Produce a hash of the build context and use that for the image name.
  let buildSig: string;

  buildSig = context ?? ".";
  if (dockerfile) {
    buildSig += `;dockerfile=${dockerfile}`;
  }
  if (args) {
    for (const arg of Object.keys(args)) {
      buildSig += `;arg[${arg}]=${args[arg]}`;
    }
  }

  buildSig += pulumi.getStack();
  return `${utils.sha1hash(buildSig)}-container`;
}
