/*
 * Copyright 2005-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.ws.transport.http;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.xml.transform.ResourceSource;
import org.springframework.xml.DocumentBuilderFactoryUtils;

public class LastModifiedHelperTest {

	private Resource resource;

	private long expected;

	@Before
	public void setUp() throws Exception {
		resource = new ClassPathResource("single.xsd", getClass());
		expected = resource.lastModified();
	}

	@Test
	public void testSaxSource() throws Exception {
		long result = LastModifiedHelper.getLastModified(new ResourceSource(resource));
		Assert.assertEquals("Invalid last modified", expected, result);
	}

	@Test
	public void testDomSource() throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactoryUtils.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = documentBuilder.parse(resource.getFile());
		long result = LastModifiedHelper.getLastModified(new DOMSource(document));
		Assert.assertEquals("Invalid last modified", expected, result);
	}

	@Test
	public void testStreamSource() throws Exception {
		long result = LastModifiedHelper.getLastModified(new StreamSource(resource.getFile()));
		Assert.assertEquals("Invalid last modified", expected, result);
	}
}