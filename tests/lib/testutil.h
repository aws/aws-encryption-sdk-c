/* 
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 * 
 *     http://aws.amazon.com/apache2.0/
 * 
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */ 

#ifndef TESTUTIL_H
#define TESTUTIL_H

/* 
 * Loads a file from disk into a newly malloc'd buffer.
 * Returns 0 on success, 1 on failure (examine errno for details)
 */
int test_loadfile(const char *filename, uint8_t **buf, size_t *datasize);

#endif
