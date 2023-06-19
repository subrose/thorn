import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Run anywhere',
    Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        Cloud, on-premise, or serverless, Subrose can run anywhere, no vendor lock-in, no strings attached.
      </>
    ),
  },
  {
    title: 'Hghly Performant',
    Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        Designed from the ground up for high performance and ultra low latency usecases, P99: &lt; 10ms.
      </>
    ),
  },
  {
    title: 'API first',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        An API first approach for compatibility with any language & framework.
      </>
    ),
  },
  {
    title: 'Audit everything',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Every action on the vault is logged with full context of the request. 
      </>
    ),
  },
  {
    title: 'PII types',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Built in support for the most common PII types, including Email, Names, SSN, DOB, and more.
      </>
    ),
  },
  {
    title: 'Flexible Policies',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Field level, access control policies to control who can access what data and when.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      {/* <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div> */}
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
